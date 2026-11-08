package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Connection States
const (
	ConnDisconnected   = "DISCONNECTED"
	ConnConnecting     = "CONNECTING"
	ConnAuthenticating = "AUTHENTICATING"
	ConnConnected      = "CONNECTED"
	ConnError          = "ERROR"
)

// Receiver Readiness & Session States
const (
	RecvIdle         = "IDLE"
	RecvInitializing = "RECEIVER_INITIALIZING"
	RecvReady        = "READY_TO_RECEIVE"
	RecvRunning      = "TEST_RUNNING"
	RecvCompleted    = "TEST_COMPLETED"
	RecvError        = "ERROR"
)

// Public IP Discovery Sources
const (
	IPValueUnknown     = "UNKNOWN"
	PublicIPSourceNone = "UNKNOWN"
	PublicIPManual     = "MANUAL"
	PublicIPDiscovered = "DISCOVERED"
)

// Test Result Classifications (Strictly Separated Stages & Verdicts)
const (
	ClassReceiverListenerReady    = "RECEIVER_LISTENER_READY"
	ClassSNATRuleInstalled        = "SNAT_RULE_INSTALLED"
	ClassLocalGenSuccess          = "LOCAL_PACKET_GENERATION_SUCCESS"
	ClassLocalRuleMatched         = "LOCAL_FIREWALL_RULE_MATCHED"
	ClassSpoofSuccess             = "SPOOF_SUCCESS"
	ClassSimulatedControlVerified = "SIMULATED_CONTROL_FLOW_VERIFIED"
	ClassRemoteNotReceived        = "REMOTE_PACKET_NOT_RECEIVED"
	ClassReceiverUnavailable      = "RECEIVER_UNAVAILABLE"
	ClassPermissionError          = "LOCAL_PERMISSION_ERROR"
	ClassRoutingError             = "ROUTING_ERROR"
	ClassTestIncomplete           = "TEST_INCOMPLETE"
)

var defaultPublicIPEndpoints = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
}

// RouteInfo holds parsed routing attributes from `ip route get <destination>`.
type RouteInfo struct {
	Destination string `json:"destination"`
	Interface   string `json:"interface"`
	SourceIP    string `json:"source_ip"`
	Gateway     string `json:"gateway,omitempty"`
}

// CommandRunner abstracts OS command execution for unit testing and security isolation.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, int, error)
	IsMock() bool
}

type RealCommandRunner struct{}

func (r *RealCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return out, exitCode, err
}

func (r *RealCommandRunner) IsMock() bool {
	return false
}

// PacketListenerBinder abstracts UDP and Raw ICMP listener binding.
type PacketListenerBinder interface {
	ListenUDP(ctx context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error)
	ListenICMP(ctx context.Context, network, address string) (net.PacketConn, error)
}

type RealListenerBinder struct{}

func (b *RealListenerBinder) ListenUDP(_ context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP(network, laddr)
}

func (b *RealListenerBinder) ListenICMP(_ context.Context, network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

// VerifiedPacketRecord stores metadata for each cryptographically verified packet.
type VerifiedPacketRecord struct {
	Seq          int    `json:"seq"`
	SourceIP     string `json:"source_ip"`
	Protocol     string `json:"protocol"`
	ICMPID       uint16 `json:"icmp_id,omitempty"`
	ICMPSeq      uint16 `json:"icmp_seq,omitempty"`
	PayloadBytes int    `json:"payload_bytes"`
	Timestamp    string `json:"timestamp"`
}

// ReceiverSession tracks an active listening session on Server B.
type ReceiverSession struct {
	SessionID        string
	Nonce            string
	ExpectedSourceIP string
	TestType         string
	UDPPort          int
	MaxPackets       int
	Generation       uint64
	StartedAt        time.Time
	ExpiresAt        time.Time

	ctx        context.Context
	CancelFunc context.CancelFunc
	DoneChan   chan struct{}

	cancelOnce sync.Once
	doneOnce   sync.Once

	mu              sync.Mutex
	cancelled       bool
	State           string
	LastError       string
	SeenSeq         map[int]bool
	VerifiedPackets []VerifiedPacketRecord
	InvalidPackets  int
	DuplicateCount  int
}

func (rs *ReceiverSession) Cancel() {
	rs.mu.Lock()
	rs.cancelled = true
	rs.mu.Unlock()

	rs.cancelOnce.Do(func() {
		if rs.CancelFunc != nil {
			rs.CancelFunc()
		}
	})
}

func (rs *ReceiverSession) IsCancelled() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.cancelled
}

func (rs *ReceiverSession) GetState() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.State
}

func (rs *ReceiverSession) markDone() {
	rs.doneOnce.Do(func() {
		close(rs.DoneChan)
	})
}

// PeerConfig holds authenticated peer details for persistent TLS connection monitoring.
type PeerConfig struct {
	Addr            string `json:"addr"`
	ControlIP       string `json:"control_ip"`
	ServerID        string `json:"server_id"`
	PublicIP        string `json:"public_ip"`
	LocalOutboundIP string `json:"local_outbound_ip,omitempty"`
	CertFingerprint string `json:"cert_fingerprint"`
	SharedSecret    string `json:"shared_secret"`
}

// TargetIP returns the routable destination IPv4 address to use when sending packets to this peer.
func (p *PeerConfig) TargetIP() string {
	if p == nil {
		return ""
	}
	if isValidIPv4(p.PublicIP) {
		return p.PublicIP
	}
	if isValidIPv4(p.ControlIP) {
		return p.ControlIP
	}
	if host, _, err := net.SplitHostPort(p.Addr); err == nil && isValidIPv4(host) {
		return host
	}
	return ""
}

// PreparedSessionInfo holds Server A's record of a prepared receiver session on Server B.
type PreparedSessionInfo struct {
	SessionID        string `json:"session_id"`
	Nonce            string `json:"nonce"`
	ExpectedSourceIP string `json:"expected_source_ip"`
	TestType         string `json:"test_type"`
	UDPPort          int    `json:"udp_port"`
	PacketCount      int    `json:"packet_count"`
}

// CrashJournalEntry records a process-owned SNAT chain on disk so a subsequent startup
// can clean up chains orphaned by a hard crash (SIGKILL/power loss) of a dead PID
// without ever touching chains belonging to live CheckSpoof processes.
type CrashJournalEntry struct {
	PID          int      `json:"pid"`
	InstanceID   string   `json:"instance_id"`
	SessionID    string   `json:"session_id"`
	ChainName    string   `json:"chain_name"`
	JumpArgs     []string `json:"jump_args"`
	ChainCreated bool     `json:"chain_created"`
	RuleAdded    bool     `json:"rule_added"`
	JumpInserted bool     `json:"jump_inserted"`
}

var journalFileMu sync.Mutex

// AppServer encapsulates the entire state of a CheckSpoof node.
type AppServer struct {
	prepMu sync.Mutex

	mu                sync.RWMutex
	ServerID          string
	InstanceChainID   string
	LocalOutboundIP   string
	LocalInterface    string
	PublicIP          string
	PublicIPSource    string
	BehindNAT         bool
	ServerIP          string
	Port              string
	PairingSecret     string
	AdminKey          string
	CertFingerprint   string
	TLSCert           tls.Certificate
	Runner            CommandRunner
	Binder            PacketListenerBinder
	PublicIPEndpoints []string
	PublicIPHTTP      *http.Client

	ConnState          string
	LocalReceiverState string
	PeerReceiverState  string
	LastHeartbeat      time.Time
	MissedHeartbeats   int
	Peer               *PeerConfig
	PreparedSession    *PreparedSessionInfo

	recvGen           uint64
	ActiveRecvSession *ReceiverSession
	SessionHistory    map[string]*ReceiverSession
	ActiveTestRunning bool

	chainsMu    sync.Mutex
	chainSeq    uint64
	OwnedChains map[string]*SNATChainIsolation
	JournalPath string

	logsMu   sync.Mutex
	LiveLogs []string

	stopOnce sync.Once
	stopCh   chan struct{}
}

func NewAppServer(runner CommandRunner) (*AppServer, error) {
	if runner == nil {
		runner = &RealCommandRunner{}
	}
	srvID := randomHex(8)
	instChainID := strings.ToUpper(srvID[:6])
	pairSecret := randomHex(16)
	adminKey := randomHex(12)

	// Detect local outbound interface and local source IP via `ip route get`.
	// Never assume this local address is the server's public IP.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	localRoute, routeErr := DetectLocalOutboundRoute(ctx, runner, "8.8.8.8")
	cancel()

	localIP := IPValueUnknown
	localIface := IPValueUnknown
	if routeErr == nil {
		if isValidIPv4(localRoute.SourceIP) {
			localIP = localRoute.SourceIP
		}
		if localRoute.Interface != "" {
			localIface = localRoute.Interface
		}
	}

	pubIP := IPValueUnknown
	pubSource := PublicIPSourceNone
	if envPub := strings.TrimSpace(os.Getenv("PUBLIC_IP")); envPub != "" {
		if IsPublicRoutableIPv4(envPub) {
			pubIP = envPub
			pubSource = PublicIPManual
		}
	}

	effectiveIP := localIP
	if isValidIPv4(pubIP) {
		effectiveIP = pubIP
	}

	cert, fp, err := generateSelfSignedCert(effectiveIP, localIP)
	if err != nil {
		return nil, err
	}

	journalPath := ""
	if !runner.IsMock() {
		journalPath = "/tmp/checkspoof_snat_journal.json"
	}

	s := &AppServer{
		ServerID:           srvID,
		InstanceChainID:    instChainID,
		LocalOutboundIP:    localIP,
		LocalInterface:     localIface,
		PublicIP:           pubIP,
		PublicIPSource:     pubSource,
		BehindNAT:          computeBehindNAT(localIP, pubIP),
		ServerIP:           effectiveIP,
		PairingSecret:      pairSecret,
		AdminKey:           adminKey,
		CertFingerprint:    fp,
		TLSCert:            cert,
		Runner:             runner,
		Binder:             &RealListenerBinder{},
		PublicIPEndpoints:  append([]string(nil), defaultPublicIPEndpoints...),
		PublicIPHTTP:       &http.Client{Timeout: 2500 * time.Millisecond},
		ConnState:          ConnDisconnected,
		LocalReceiverState: RecvIdle,
		PeerReceiverState:  RecvIdle,
		SessionHistory:     make(map[string]*ReceiverSession),
		OwnedChains:        make(map[string]*SNATChainIsolation),
		JournalPath:        journalPath,
		stopCh:             make(chan struct{}),
	}
	return s, nil
}

func computeBehindNAT(localIP, publicIP string) bool {
	if !isValidIPv4(localIP) {
		return false
	}
	if IsPrivateOrReservedLocalIPv4(localIP) {
		return true
	}
	if isValidIPv4(publicIP) && publicIP != localIP {
		return true
	}
	return false
}

// EffectiveControlIP returns the best known control IPv4 address for pairing/listening.
func (s *AppServer) EffectiveControlIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.effectiveControlIPLocked()
}

func (s *AppServer) effectiveControlIPLocked() string {
	if isValidIPv4(s.PublicIP) {
		return s.PublicIP
	}
	if isValidIPv4(s.ServerIP) {
		return s.ServerIP
	}
	if isValidIPv4(s.LocalOutboundIP) {
		return s.LocalOutboundIP
	}
	return IPValueUnknown
}

// SetManualPublicIP configures an explicit public IPv4 address.
func (s *AppServer) SetManualPublicIP(ipStr string) error {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || strings.EqualFold(ipStr, IPValueUnknown) {
		s.mu.Lock()
		s.PublicIP = IPValueUnknown
		s.PublicIPSource = PublicIPSourceNone
		if isValidIPv4(s.LocalOutboundIP) {
			s.ServerIP = s.LocalOutboundIP
		} else {
			s.ServerIP = IPValueUnknown
		}
		s.BehindNAT = computeBehindNAT(s.LocalOutboundIP, s.PublicIP)
		s.mu.Unlock()
		return nil
	}

	if !isValidIPv4(ipStr) {
		return fmt.Errorf("invalid public IPv4 address: %s", ipStr)
	}
	if IsPrivateOrReservedLocalIPv4(ipStr) {
		return fmt.Errorf("address %s is private, loopback, or reserved; manual public IP must be a public routable IPv4", ipStr)
	}

	s.mu.Lock()
	localIP := s.LocalOutboundIP
	s.mu.Unlock()

	cert, fp, err := generateSelfSignedCert(ipStr, localIP)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.PublicIP = ipStr
	s.PublicIPSource = PublicIPManual
	s.ServerIP = ipStr
	s.BehindNAT = computeBehindNAT(s.LocalOutboundIP, s.PublicIP)
	s.TLSCert = cert
	s.CertFingerprint = fp
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("[Network] Public IP manually configured to %s (LocalOutbound=%s, BehindNAT=%v)", ipStr, localIP, s.BehindNAT))
	return nil
}

// DiscoverAndSetPublicIP queries external public IP discovery endpoints.
func (s *AppServer) DiscoverAndSetPublicIP(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.PublicIPSource == PublicIPManual && isValidIPv4(s.PublicIP) {
		pub := s.PublicIP
		s.mu.RUnlock()
		return pub, nil
	}
	endpoints := append([]string(nil), s.PublicIPEndpoints...)
	client := s.PublicIPHTTP
	localIP := s.LocalOutboundIP
	s.mu.RUnlock()

	discovered, err := DiscoverPublicIP(ctx, client, endpoints)
	if err != nil || !IsPublicRoutableIPv4(discovered) {
		s.mu.Lock()
		if s.PublicIPSource != PublicIPManual {
			s.PublicIP = IPValueUnknown
			s.PublicIPSource = PublicIPSourceNone
			s.BehindNAT = computeBehindNAT(s.LocalOutboundIP, s.PublicIP)
		}
		s.mu.Unlock()
		if err == nil {
			err = errors.New("public IP discovery returned non-public address")
		}
		return IPValueUnknown, err
	}

	cert, fp, certErr := generateSelfSignedCert(discovered, localIP)
	s.mu.Lock()
	s.PublicIP = discovered
	s.PublicIPSource = PublicIPDiscovered
	s.ServerIP = discovered
	s.BehindNAT = computeBehindNAT(s.LocalOutboundIP, s.PublicIP)
	if certErr == nil {
		s.TLSCert = cert
		s.CertFingerprint = fp
	}
	s.mu.Unlock()

	return discovered, nil
}

// DiscoverPublicIP queries one or more HTTP endpoints for the server's public IPv4 address.
func DiscoverPublicIP(ctx context.Context, client *http.Client, endpoints []string) (string, error) {
	if len(endpoints) == 0 {
		return IPValueUnknown, errors.New("no public IP discovery endpoints configured")
	}
	if client == nil {
		client = &http.Client{Timeout: 2500 * time.Millisecond}
	}

	var confirmedIP string
	var lastErr error

	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("endpoint %s returned HTTP %d", ep, resp.StatusCode)
			continue
		}
		candidate := strings.TrimSpace(string(bodyBytes))
		if !IsPublicRoutableIPv4(candidate) {
			lastErr = fmt.Errorf("endpoint %s returned non-public or invalid IPv4: %q", ep, candidate)
			continue
		}
		if confirmedIP == "" {
			confirmedIP = candidate
		} else if confirmedIP != candidate {
			return IPValueUnknown, fmt.Errorf("uncertain public IP: conflicting responses (%s vs %s)", confirmedIP, candidate)
		}
	}

	if confirmedIP == "" {
		if lastErr != nil {
			return IPValueUnknown, lastErr
		}
		return IPValueUnknown, errors.New("unable to determine public IP")
	}
	return confirmedIP, nil
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *AppServer) AddLog(msg string) {
	s.logsMu.Lock()
	defer s.logsMu.Unlock()
	ts := time.Now().Format("15:04:05.000")
	line := fmt.Sprintf("[%s] %s", ts, msg)
	if len(s.LiveLogs) >= 150 {
		s.LiveLogs = s.LiveLogs[1:]
	}
	s.LiveLogs = append(s.LiveLogs, line)
}

func (s *AppServer) PairingToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctrlIP := s.effectiveControlIPLocked()
	return fmt.Sprintf("%s:%s|%s|%s|%s", ctrlIP, s.Port, s.ServerID, s.CertFingerprint, s.PairingSecret)
}

func ParsePairingToken(token string) (*PeerConfig, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, "|")
	if len(parts) != 4 {
		return nil, errors.New("فرمت توکن نامعتبر است؛ فرمت صحیح: IP:PORT|SERVER_ID|CERT_FP|SECRET")
	}
	addr, srvID, fp, secret := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3])
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("آدرس IP یا پورت داخل توکن نامعتبر است")
	}
	if strings.EqualFold(host, IPValueUnknown) {
		return nil, errors.New("آدرس IP داخل توکن UNKNOWN است؛ لطفاً در سرور مقابل آدرس IP عمومی (-public-ip) را تنظیم کنید")
	}
	if !isValidIPv4(host) {
		return nil, errors.New("آدرس IP داخل توکن معتبر نیست")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return nil, errors.New("پورت داخل توکن نامعتبر است")
	}
	if len(srvID) < 8 || len(fp) != 64 || len(secret) < 16 {
		return nil, errors.New("فیلدهای امنیتی توکن ناقص یا نامعتبر هستند")
	}

	pubIP := IPValueUnknown
	localIP := ""
	if IsPublicRoutableIPv4(host) {
		pubIP = host
	} else {
		localIP = host
	}

	return &PeerConfig{
		Addr:            addr,
		ControlIP:       host,
		ServerID:        srvID,
		PublicIP:        pubIP,
		LocalOutboundIP: localIP,
		CertFingerprint: strings.ToLower(fp),
		SharedSecret:    secret,
	}, nil
}

func generateSelfSignedCert(ips ...string) (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	cn := "checkspoof-node"
	ipList := []net.IP{net.ParseIP("127.0.0.1")}
	seen := map[string]bool{"127.0.0.1": true}
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if parsed := net.ParseIP(ipStr); parsed != nil && parsed.To4() != nil {
			s := parsed.To4().String()
			if cn == "checkspoof-node" {
				cn = s
			}
			if !seen[s] {
				seen[s] = true
				ipList = append(ipList, parsed.To4())
			}
		}
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CheckSpoof Diagnostic Node"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ipList,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(derBytes)
	fp := hex.EncodeToString(sum[:])

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, fp, err
}

func (s *AppServer) buildPeerTLSClient(expectedFP string, timeout time.Duration) *http.Client {
	expectedFP = strings.ToLower(strings.TrimSpace(expectedFP))
	s.mu.RLock()
	localCert := s.TLSCert
	s.mu.RUnlock()

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{localCert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer presented no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			actualFP := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(actualFP), []byte(expectedFP)) != 1 {
				return fmt.Errorf("TLS certificate fingerprint mismatch: expected %s, got %s", expectedFP, actualFP)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

func signPeerRequest(secret, method, path, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(method + "|" + path + "|" + timestamp + "|"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *AppServer) doPeerRequest(ctx context.Context, peer *PeerConfig, path string, payload interface{}, out interface{}, timeout time.Duration) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s%s", peer.Addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signPeerRequest(peer.SharedSecret, http.MethodPost, path, ts, bodyBytes)

	s.mu.RLock()
	srvID := s.ServerID
	certFP := s.CertFingerprint
	s.mu.RUnlock()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Peer-ID", srvID)
	req.Header.Set("X-Peer-Cert-FP", certFP)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Peer-Signature", sig)

	client := s.buildPeerTLSClient(peer.CertFingerprint, timeout)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}

// Packet Framing & Cryptographic Verification

func BuildUDPPacketPayload(secret, sessionID, nonce string, seq int, tsMillis int64) []byte {
	core := fmt.Sprintf("CSPFv2|%s|udp|%d|%d|%s", sessionID, seq, tsMillis, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(core))
	sig := hex.EncodeToString(mac.Sum(nil))
	return []byte(core + "|" + sig)
}

func ValidateUDPPacketPayload(payload []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (int, error) {
	parts := strings.Split(strings.TrimSpace(string(payload)), "|")
	if len(parts) != 7 {
		return 0, errors.New("invalid CSPFv2 frame format")
	}
	if parts[0] != "CSPFv2" || parts[2] != "udp" {
		return 0, errors.New("invalid protocol header or method")
	}
	if parts[1] != expectedSessionID {
		return 0, errors.New("session ID mismatch")
	}
	if parts[5] != expectedNonce {
		return 0, errors.New("nonce mismatch")
	}
	seq, err := strconv.Atoi(parts[3])
	if err != nil || seq < 1 || seq > maxPackets {
		return 0, errors.New("sequence number out of bounds")
	}
	tsMillis, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return 0, errors.New("invalid timestamp")
	}
	diff := time.Since(time.UnixMilli(tsMillis))
	if diff < -60*time.Second || diff > 120*time.Second {
		return 0, errors.New("packet timestamp expired (replay protection)")
	}
	core := strings.Join(parts[:6], "|")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(core))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[6]), []byte(expectedSig)) != 1 {
		return 0, errors.New("HMAC signature verification failed")
	}
	return seq, nil
}

func BuildICMPPatternHex(secret, sessionID, nonce string, seq int) (string, error) {
	sessBytes, err := hex.DecodeString(sessionID)
	if err != nil || len(sessBytes) < 4 {
		return "", errors.New("invalid sessionID hex")
	}
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil || len(nonceBytes) < 4 {
		return "", errors.New("invalid nonce hex")
	}
	if seq < 1 || seq > 255 {
		return "", errors.New("seq out of 1..255 range")
	}
	frame := make([]byte, 16)
	frame[0] = 0xC5
	copy(frame[1:5], sessBytes[:4])
	frame[5] = byte(seq)
	copy(frame[6:10], nonceBytes[:4])

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(frame[:10])
	sum := mac.Sum(nil)
	copy(frame[10:16], sum[:6])

	return hex.EncodeToString(frame), nil
}

func ValidateICMPRawPacket(rawPkt []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (seq int, icmpID uint16, icmpSeq uint16, err error) {
	if len(rawPkt) < 24 {
		return 0, 0, 0, errors.New("ICMP packet too short")
	}
	offset := 0
	if (rawPkt[0] >> 4) == 4 {
		ihl := int(rawPkt[0]&0x0f) * 4
		if len(rawPkt) >= ihl+8 && rawPkt[offset+ihl] == 8 {
			offset = ihl
		}
	}
	icmpPkt := rawPkt[offset:]
	if len(icmpPkt) < 24 {
		return 0, 0, 0, errors.New("ICMP frame too short")
	}
	if icmpPkt[0] != 8 || icmpPkt[1] != 0 {
		return 0, 0, 0, fmt.Errorf("not an ICMP Echo Request (type=%d, code=%d)", icmpPkt[0], icmpPkt[1])
	}
	icmpID = binary.BigEndian.Uint16(icmpPkt[4:6])
	icmpSeq = binary.BigEndian.Uint16(icmpPkt[6:8])
	payload := icmpPkt[8:]

	sessBytes, err := hex.DecodeString(expectedSessionID)
	if err != nil || len(sessBytes) < 4 {
		return 0, 0, 0, errors.New("invalid expected session ID")
	}
	nonceBytes, err := hex.DecodeString(expectedNonce)
	if err != nil || len(nonceBytes) < 4 {
		return 0, 0, 0, errors.New("invalid expected nonce")
	}

	for i := 0; i <= len(payload)-16; i++ {
		chunk := payload[i : i+16]
		if chunk[0] != 0xC5 {
			continue
		}
		if !bytes.Equal(chunk[1:5], sessBytes[:4]) {
			continue
		}
		pktSeq := int(chunk[5])
		if pktSeq < 1 || pktSeq > maxPackets {
			continue
		}
		if !bytes.Equal(chunk[6:10], nonceBytes[:4]) {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(chunk[:10])
		expectedMAC := mac.Sum(nil)[:6]
		if subtle.ConstantTimeCompare(chunk[10:16], expectedMAC) == 1 {
			return pktSeq, icmpID, icmpSeq, nil
		}
	}
	return 0, 0, 0, errors.New("no valid CheckSpoof cryptographic signature found in ICMP payload")
}

// Process/Session-Scoped Isolated iptables SNAT Chain Lifecycle Management

// SNATChainIsolation tracks the exact firewall resources created by a single test session
// so cleanup removes ONLY resources owned by that session and safely rolls back partial state.
type SNATChainIsolation struct {
	ChainName    string
	InstanceID   string
	SessionID    string
	JumpArgs     []string
	RuleArgs     []string
	Runner       CommandRunner
	Server       *AppServer
	chainCreated bool
	ruleAdded    bool
	jumpInserted bool
	cleaned      bool
	mu           sync.Mutex
}

func sanitizeAlphaNumUpper(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
			if b.Len() >= maxLen {
				break
			}
		}
	}
	return b.String()
}

// BuildSNATChainName generates a process- and session-scoped iptables chain name:
// Format: CSPF_<6CharInstanceID>_<8CharSessionTag> (max 20 chars, well under Linux's 28-char limit).
func (s *AppServer) BuildSNATChainName(sessionID string) string {
	inst := sanitizeAlphaNumUpper(s.InstanceChainID, 6)
	if len(inst) < 6 {
		inst = sanitizeAlphaNumUpper(s.ServerID, 6)
	}
	if inst == "" {
		inst = "NODE00"
	}
	sess := sanitizeAlphaNumUpper(sessionID, 8)
	if sess == "" {
		seq := atomic.AddUint64(&s.chainSeq, 1)
		sess = fmt.Sprintf("S%07X", seq&0xFFFFFFF)
	}
	return fmt.Sprintf("CSPF_%s_%s", inst, sess)
}

func (s *AppServer) allocateUniqueChainName(sessionID string) string {
	base := s.BuildSNATChainName(sessionID)
	s.chainsMu.Lock()
	defer s.chainsMu.Unlock()

	if _, exists := s.OwnedChains[base]; !exists {
		return base
	}
	// If the caller passed a duplicate sessionID while a chain with that ID is still active,
	// disambiguate using the monotonic per-instance chain sequence so we never clobber an active session.
	inst := sanitizeAlphaNumUpper(s.InstanceChainID, 6)
	for {
		seq := atomic.AddUint64(&s.chainSeq, 1)
		candidate := fmt.Sprintf("CSPF_%s_%08X", inst, seq&0xFFFFFFFF)
		if _, exists := s.OwnedChains[candidate]; !exists {
			return candidate
		}
	}
}

// SetupIsolatedSNATChain creates a uniquely identifiable per-process/per-session NAT chain,
// tracks each initialization step for safe partial-failure rollback, and records ownership.
func (s *AppServer) SetupIsolatedSNATChain(ctx context.Context, sessionID, iface, targetIP, spoofIP, proto string, udpPort int) (*SNATChainIsolation, error) {
	chainName := s.allocateUniqueChainName(sessionID)

	var ruleArgs []string
	var jumpSpec []string
	if proto == "udp" {
		portStr := strconv.Itoa(udpPort)
		ruleArgs = []string{"-t", "nat", "-A", chainName, "-o", iface, "-d", targetIP, "-p", "udp", "--dport", portStr, "-j", "SNAT", "--to-source", spoofIP}
		jumpSpec = []string{"-o", iface, "-d", targetIP, "-p", "udp", "--dport", portStr, "-j", chainName}
	} else {
		ruleArgs = []string{"-t", "nat", "-A", chainName, "-o", iface, "-d", targetIP, "-p", "icmp", "-j", "SNAT", "--to-source", spoofIP}
		jumpSpec = []string{"-o", iface, "-d", targetIP, "-p", "icmp", "-j", chainName}
	}

	iso := &SNATChainIsolation{
		ChainName:  chainName,
		InstanceID: s.InstanceChainID,
		SessionID:  sessionID,
		JumpArgs:   jumpSpec,
		RuleArgs:   ruleArgs,
		Runner:     s.Runner,
		Server:     s,
	}

	// Register ownership in s.OwnedChains before executing iptables commands so concurrent
	// Shutdown/CleanupAllChains calls are aware of in-progress or active chains.
	s.chainsMu.Lock()
	s.OwnedChains[chainName] = iso
	s.chainsMu.Unlock()

	// Step 1: Create dedicated chain (-N). Never pre-flush or pre-delete before -N,
	// so we can never accidentally destroy an existing chain.
	if out, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-N", chainName); err != nil {
		s.chainsMu.Lock()
		delete(s.OwnedChains, chainName)
		s.chainsMu.Unlock()
		return nil, fmt.Errorf("failed to create isolated iptables chain %s: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	iso.mu.Lock()
	iso.chainCreated = true
	iso.mu.Unlock()
	s.syncCrashJournal()

	// Step 2: Insert SNAT rule inside our newly created chain (-A).
	if out, _, err := s.Runner.Run(ctx, "iptables", ruleArgs...); err != nil {
		iso.Cleanup()
		return nil, fmt.Errorf("failed to insert SNAT rule into %s: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	iso.mu.Lock()
	iso.ruleAdded = true
	iso.mu.Unlock()
	s.syncCrashJournal()

	// Step 3: Verify rule creation and target SNAT address inside our dedicated chain.
	verifyOut, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-L", chainName, "-v", "-n", "-x")
	if err != nil || !strings.Contains(string(verifyOut), "to:"+spoofIP) {
		iso.Cleanup()
		return nil, fmt.Errorf("failed to verify SNAT rule in chain %s", chainName)
	}

	// Step 4: Hook chain into POSTROUTING (-I POSTROUTING 1).
	insertArgs := append([]string{"-t", "nat", "-I", "POSTROUTING", "1"}, jumpSpec...)
	if out, _, err := s.Runner.Run(ctx, "iptables", insertArgs...); err != nil {
		iso.Cleanup()
		return nil, fmt.Errorf("failed to hook chain %s into POSTROUTING: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	iso.mu.Lock()
	iso.jumpInserted = true
	iso.mu.Unlock()
	s.syncCrashJournal()

	return iso, nil
}

// ReadCounters reads exact packet and byte counters exclusively from the session's isolated chain.
func (c *SNATChainIsolation) ReadCounters(ctx context.Context) (packets int, bytesCount int, rawOutput string, err error) {
	out, _, err := c.Runner.Run(ctx, "iptables", "-t", "nat", "-L", c.ChainName, "-v", "-n", "-x")
	rawOutput = string(out)
	if err != nil {
		return 0, 0, rawOutput, err
	}
	packets, bytesCount, err = ParseIsolatedChainCounters(rawOutput)
	return packets, bytesCount, rawOutput, err
}

func ParseIsolatedChainCounters(output string) (int, int, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts ") {
			continue
		}
		if strings.Contains(line, "SNAT") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pkts, err1 := strconv.Atoi(fields[0])
				bCount, err2 := strconv.Atoi(fields[1])
				if err1 == nil && err2 == nil {
					return pkts, bCount, nil
				}
			}
		}
	}
	return 0, 0, errors.New("SNAT rule counter line not found in isolated chain output")
}

// Cleanup safely, idempotently, and concurrency-safely removes ONLY the firewall resources
// created by this specific SNATChainIsolation session.
func (c *SNATChainIsolation) Cleanup() {
	c.mu.Lock()
	if c.cleaned {
		c.mu.Unlock()
		return
	}
	c.cleaned = true
	jumpInserted := c.jumpInserted
	chainCreated := c.chainCreated
	jumpArgs := append([]string(nil), c.JumpArgs...)
	chainName := c.ChainName
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Remove POSTROUTING jump rule ONLY if it was actually inserted by this session.
	if jumpInserted && len(jumpArgs) > 0 {
		delArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, jumpArgs...)
		_, _, _ = c.Runner.Run(ctx, "iptables", delArgs...)
	}

	// Flush and delete the isolated chain ONLY if it was actually created by this session.
	if chainCreated && chainName != "" {
		_, _, _ = c.Runner.Run(ctx, "iptables", "-t", "nat", "-F", chainName)
		_, _, _ = c.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)
	}

	if c.Server != nil {
		c.Server.chainsMu.Lock()
		delete(c.Server.OwnedChains, chainName)
		c.Server.chainsMu.Unlock()
		c.Server.syncCrashJournal()
	}
}

// CleanupAllChains cleans up ONLY the SNAT chains and rules owned by this AppServer instance.
// It never sweeps or deletes chains belonging to other CheckSpoof processes or unrelated firewall rules.
func (s *AppServer) CleanupAllChains() {
	s.chainsMu.Lock()
	owned := make([]*SNATChainIsolation, 0, len(s.OwnedChains))
	for _, iso := range s.OwnedChains {
		owned = append(owned, iso)
	}
	s.chainsMu.Unlock()

	for _, iso := range owned {
		iso.Cleanup()
	}
}

// Crash Recovery Journal Helpers

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (s *AppServer) syncCrashJournal() {
	if s.JournalPath == "" {
		return
	}

	s.chainsMu.Lock()
	myEntries := make([]CrashJournalEntry, 0, len(s.OwnedChains))
	for _, iso := range s.OwnedChains {
		iso.mu.Lock()
		if !iso.cleaned && iso.chainCreated {
			myEntries = append(myEntries, CrashJournalEntry{
				PID:          os.Getpid(),
				InstanceID:   s.InstanceChainID,
				SessionID:    iso.SessionID,
				ChainName:    iso.ChainName,
				JumpArgs:     append([]string(nil), iso.JumpArgs...),
				ChainCreated: iso.chainCreated,
				RuleAdded:    iso.ruleAdded,
				JumpInserted: iso.jumpInserted,
			})
		}
		iso.mu.Unlock()
	}
	s.chainsMu.Unlock()

	journalFileMu.Lock()
	defer journalFileMu.Unlock()

	var existing []CrashJournalEntry
	if data, err := os.ReadFile(s.JournalPath); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &existing)
	}

	// Preserve entries from other AppServer instances; replace only this instance's entries.
	merged := make([]CrashJournalEntry, 0, len(existing)+len(myEntries))
	for _, e := range existing {
		if e.InstanceID != s.InstanceChainID {
			merged = append(merged, e)
		}
	}
	merged = append(merged, myEntries...)

	if len(merged) == 0 {
		_ = os.Remove(s.JournalPath)
		return
	}
	if encoded, err := json.MarshalIndent(merged, "", "  "); err == nil {
		_ = os.WriteFile(s.JournalPath, encoded, 0600)
	}
}

// RecoverOrphanedChainsFromJournal inspects the crash journal and cleans up ONLY chains
// whose owning process PID is no longer alive. Chains belonging to live processes are untouched.
func (s *AppServer) RecoverOrphanedChainsFromJournal(ctx context.Context) int {
	if s.JournalPath == "" {
		return 0
	}

	journalFileMu.Lock()
	defer journalFileMu.Unlock()

	data, err := os.ReadFile(s.JournalPath)
	if err != nil || len(data) == 0 {
		return 0
	}
	var entries []CrashJournalEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0
	}

	var surviving []CrashJournalEntry
	recovered := 0
	for _, e := range entries {
		if isProcessAlive(e.PID) {
			surviving = append(surviving, e)
			continue
		}
		if e.JumpInserted && len(e.JumpArgs) > 0 {
			delArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, e.JumpArgs...)
			_, _, _ = s.Runner.Run(ctx, "iptables", delArgs...)
		}
		if e.ChainCreated && e.ChainName != "" {
			_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", e.ChainName)
			_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", e.ChainName)
		}
		recovered++
	}

	if len(surviving) == 0 {
		_ = os.Remove(s.JournalPath)
	} else if encoded, err := json.MarshalIndent(surviving, "", "  "); err == nil {
		_ = os.WriteFile(s.JournalPath, encoded, 0600)
	}
	return recovered
}

// Routing & Outbound Interface / Source IP Discovery via `ip route get`

func ParseIPRouteGetOutput(output string) (RouteInfo, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 {
		return RouteInfo{}, errors.New("empty ip route get output")
	}

	var info RouteInfo
	for i := 0; i < len(fields); i++ {
		w := fields[i]
		switch w {
		case "local", "unicast", "broadcast", "multicast":
			if i+1 < len(fields) && isValidIPv4(fields[i+1]) && info.Destination == "" {
				info.Destination = fields[i+1]
			}
		case "via":
			if i+1 < len(fields) && isValidIPv4(fields[i+1]) {
				info.Gateway = fields[i+1]
				i++
			}
		case "dev":
			if i+1 < len(fields) {
				info.Interface = fields[i+1]
				i++
			}
		case "src":
			if i+1 < len(fields) && isValidIPv4(fields[i+1]) {
				info.SourceIP = fields[i+1]
				i++
			}
		default:
			if i == 0 && isValidIPv4(w) {
				info.Destination = w
			}
		}
	}

	if info.Interface == "" {
		return info, fmt.Errorf("no outgoing interface (dev) found in route output: %s", strings.TrimSpace(output))
	}
	if info.SourceIP == "" {
		return info, fmt.Errorf("no local source IP (src) found in route output: %s", strings.TrimSpace(output))
	}
	return info, nil
}

func DetectLocalOutboundRoute(ctx context.Context, runner CommandRunner, targetIP string) (RouteInfo, error) {
	if !isValidIPv4(targetIP) {
		return RouteInfo{}, fmt.Errorf("invalid target IPv4 address: %s", targetIP)
	}
	if runner == nil {
		runner = &RealCommandRunner{}
	}
	out, exitCode, err := runner.Run(ctx, "ip", "route", "get", targetIP)
	if err != nil || exitCode != 0 {
		return RouteInfo{}, fmt.Errorf("route lookup failed for %s: %v (%s)", targetIP, err, strings.TrimSpace(string(out)))
	}
	return ParseIPRouteGetOutput(string(out))
}

func (s *AppServer) ResolveRoute(ctx context.Context, targetIP string) (RouteInfo, error) {
	info, err := DetectLocalOutboundRoute(ctx, s.Runner, targetIP)
	if err != nil {
		return RouteInfo{}, err
	}
	s.mu.Lock()
	if s.LocalOutboundIP == IPValueUnknown && isValidIPv4(info.SourceIP) {
		s.LocalOutboundIP = info.SourceIP
		s.BehindNAT = computeBehindNAT(s.LocalOutboundIP, s.PublicIP)
	}
	if s.LocalInterface == IPValueUnknown && info.Interface != "" {
		s.LocalInterface = info.Interface
	}
	s.mu.Unlock()
	return info, nil
}

func (s *AppServer) ResolveOutgoingInterface(ctx context.Context, targetIP string) (string, error) {
	info, err := s.ResolveRoute(ctx, targetIP)
	if err != nil {
		return "", err
	}
	return info.Interface, nil
}

// Receiver Readiness & Deadlock-Free Background Packet Listener Lifecycle

type PeerPrepareRequest struct {
	SessionID        string `json:"session_id"`
	Nonce            string `json:"nonce"`
	ExpectedSourceIP string `json:"expected_source_ip"`
	TestType         string `json:"test_type"`
	UDPPort          int    `json:"udp_port"`
	MaxPackets       int    `json:"max_packets"`
	TimeoutSec       int    `json:"timeout_sec"`
}

type PeerPrepareResponse struct {
	SessionID     string `json:"session_id"`
	ReceiverState string `json:"receiver_state"`
	BoundAddress  string `json:"bound_address"`
	Message       string `json:"message"`
}

func (s *AppServer) StartReceiverSession(req PeerPrepareRequest, sharedSecret string) (*PeerPrepareResponse, error) {
	return s.StartReceiverSessionWithContext(context.Background(), req, sharedSecret)
}

func (s *AppServer) StartReceiverSessionWithContext(callerCtx context.Context, req PeerPrepareRequest, sharedSecret string) (*PeerPrepareResponse, error) {
	if callerCtx == nil {
		callerCtx = context.Background()
	}

	if !isValidIPv4(req.ExpectedSourceIP) {
		return nil, errors.New("invalid expected_source_ip")
	}
	if req.TestType != "icmp" && req.TestType != "udp" {
		return nil, errors.New("unsupported test_type (must be icmp or udp)")
	}
	if req.UDPPort <= 0 || req.UDPPort > 65535 {
		req.UDPPort = 5555
	}
	if req.MaxPackets <= 0 || req.MaxPackets > 20 {
		req.MaxPackets = 5
	}
	if req.TimeoutSec <= 0 || req.TimeoutSec > 60 {
		req.TimeoutSec = 30
	}
	if req.SessionID == "" {
		req.SessionID = randomHex(16)
	}
	if req.Nonce == "" {
		req.Nonce = randomHex(16)
	}

	s.prepMu.Lock()
	defer s.prepMu.Unlock()

	s.mu.Lock()
	oldSess := s.ActiveRecvSession
	s.recvGen++
	myGen := s.recvGen

	sessCtx, sessCancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutSec)*time.Second)
	sess := &ReceiverSession{
		SessionID:        req.SessionID,
		Nonce:            req.Nonce,
		ExpectedSourceIP: req.ExpectedSourceIP,
		TestType:         req.TestType,
		UDPPort:          req.UDPPort,
		MaxPackets:       req.MaxPackets,
		Generation:       myGen,
		StartedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Duration(req.TimeoutSec) * time.Second),
		ctx:              sessCtx,
		CancelFunc:       sessCancel,
		DoneChan:         make(chan struct{}),
		State:            RecvInitializing,
		SeenSeq:          make(map[int]bool),
		VerifiedPackets:  []VerifiedPacketRecord{},
	}

	if callerCtx.Err() != nil {
		sess.cancelled = true
	}

	s.ActiveRecvSession = sess
	if len(s.SessionHistory) >= 32 {
		s.SessionHistory = make(map[string]*ReceiverSession)
	}
	s.SessionHistory[sess.SessionID] = sess
	s.LocalReceiverState = RecvInitializing
	s.mu.Unlock()

	watchDone := make(chan struct{})
	go func() {
		select {
		case <-callerCtx.Done():
			sess.Cancel()
		case <-s.stopCh:
			sess.Cancel()
		case <-sess.DoneChan:
		case <-watchDone:
		}
	}()
	defer close(watchDone)

	if oldSess != nil {
		oldSess.Cancel()
		<-oldSess.DoneChan
	}

	if sess.IsCancelled() || sessCtx.Err() != nil || callerCtx.Err() != nil {
		s.abortStartupSession(sess, RecvIdle, "session cancelled before listener initialization")
		return nil, errors.New("receiver session cancelled before listener initialization")
	}

	binder := s.Binder
	if binder == nil {
		binder = &RealListenerBinder{}
	}

	if req.TestType == "udp" {
		bindAddr := fmt.Sprintf("0.0.0.0:%d", req.UDPPort)
		udpAddr, err := net.ResolveUDPAddr("udp4", bindAddr)
		if err != nil {
			s.abortStartupSession(sess, RecvError, err.Error())
			return nil, err
		}
		conn, err := binder.ListenUDP(sessCtx, "udp4", udpAddr)
		if err != nil {
			s.abortStartupSession(sess, RecvError, err.Error())
			s.AddLog(fmt.Sprintf("[-] [Receiver] Failed to bind UDP listener on %s: %v", bindAddr, err))
			return nil, fmt.Errorf("UDP socket bind failed on %s: %v", bindAddr, err)
		}

		sess.mu.Lock()
		if sess.cancelled || sessCtx.Err() != nil || callerCtx.Err() != nil {
			sess.State = RecvError
			sess.LastError = "cancelled during UDP listener startup"
			sess.mu.Unlock()
			_ = conn.Close()
			s.abortStartupSession(sess, RecvIdle, "cancelled during UDP listener startup")
			return nil, errors.New("receiver session cancelled during UDP listener initialization")
		}
		sess.State = RecvReady
		sess.mu.Unlock()

		actualAddr := conn.LocalAddr().String()
		s.mu.Lock()
		if s.recvGen == sess.Generation {
			s.LocalReceiverState = RecvReady
		}
		s.mu.Unlock()

		s.AddLog(fmt.Sprintf("🟢 [Receiver] READY_TO_RECEIVE on UDP %s (Session=%s, ExpectSource=%s)", actualAddr, req.SessionID[:8], req.ExpectedSourceIP))
		go s.runUDPReceiverLoop(sessCtx, conn, sess, sharedSecret)

		return &PeerPrepareResponse{
			SessionID:     req.SessionID,
			ReceiverState: RecvReady,
			BoundAddress:  actualAddr,
			Message:       "UDP listener bound and ready to receive",
		}, nil
	}

	conn, err := binder.ListenICMP(sessCtx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		s.abortStartupSession(sess, RecvError, err.Error())
		s.AddLog(fmt.Sprintf("[-] [Receiver] Failed to bind ip4:icmp socket (CAP_NET_RAW required): %v", err))
		return nil, fmt.Errorf("raw ICMP socket bind failed (requires root/CAP_NET_RAW): %v", err)
	}

	sess.mu.Lock()
	if sess.cancelled || sessCtx.Err() != nil || callerCtx.Err() != nil {
		sess.State = RecvError
		sess.LastError = "cancelled during ICMP listener startup"
		sess.mu.Unlock()
		_ = conn.Close()
		s.abortStartupSession(sess, RecvIdle, "cancelled during ICMP listener startup")
		return nil, errors.New("receiver session cancelled during ICMP listener initialization")
	}
	sess.State = RecvReady
	sess.mu.Unlock()

	s.mu.Lock()
	if s.recvGen == sess.Generation {
		s.LocalReceiverState = RecvReady
	}
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🟢 [Receiver] READY_TO_RECEIVE on ip4:icmp (Session=%s, ExpectSource=%s)", req.SessionID[:8], req.ExpectedSourceIP))
	go s.runICMPReceiverLoop(sessCtx, conn, sess, sharedSecret)

	return &PeerPrepareResponse{
		SessionID:     req.SessionID,
		ReceiverState: RecvReady,
		BoundAddress:  "ip4:icmp:0.0.0.0",
		Message:       "Raw ICMP listener bound and ready to receive",
	}, nil
}

func (s *AppServer) abortStartupSession(sess *ReceiverSession, serverState string, errMsg string) {
	sess.Cancel()

	sess.mu.Lock()
	sess.State = RecvError
	sess.LastError = errMsg
	sess.mu.Unlock()

	s.mu.Lock()
	if s.recvGen == sess.Generation && s.ActiveRecvSession == sess {
		s.LocalReceiverState = serverState
		if serverState == RecvIdle {
			s.ActiveRecvSession = nil
		}
	}
	s.mu.Unlock()

	sess.markDone()
}

func (s *AppServer) onSessionExit(sess *ReceiverSession, finalServerState string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recvGen == sess.Generation && s.ActiveRecvSession == sess {
		s.LocalReceiverState = finalServerState
	}
}

func (s *AppServer) StopActiveReceiverSession() {
	s.mu.RLock()
	sess := s.ActiveRecvSession
	s.mu.RUnlock()
	if sess != nil {
		sess.Cancel()
		<-sess.DoneChan
	}
}

func (s *AppServer) CancelReceiverSession(sessionID string) bool {
	s.mu.RLock()
	var sess *ReceiverSession
	if sessionID != "" {
		sess = s.SessionHistory[sessionID]
	}
	if sess == nil && s.ActiveRecvSession != nil && (sessionID == "" || s.ActiveRecvSession.SessionID == sessionID) {
		sess = s.ActiveRecvSession
	}
	s.mu.RUnlock()

	if sess == nil {
		return false
	}
	sess.Cancel()
	<-sess.DoneChan
	return true
}

func (s *AppServer) runUDPReceiverLoop(ctx context.Context, conn net.PacketConn, sess *ReceiverSession, secret string) {
	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() {
			_ = conn.Close()
		})
	}

	defer func() {
		closeConn()
		sess.Cancel()

		finalServerState := RecvIdle
		sess.mu.Lock()
		if sess.State == RecvReady || sess.State == RecvRunning || sess.State == RecvInitializing {
			sess.State = RecvCompleted
		} else if sess.State == RecvError {
			finalServerState = RecvError
		}
		sess.mu.Unlock()

		s.onSessionExit(sess, finalServerState)
		sess.markDone()
		s.AddLog(fmt.Sprintf("🏁 [Receiver] UDP session %s closed.", sess.SessionID[:8]))
	}()

	go func() {
		select {
		case <-ctx.Done():
			closeConn()
		case <-sess.DoneChan:
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || sess.IsCancelled() {
				return
			}
			sess.mu.Lock()
			sess.State = RecvError
			sess.LastError = err.Error()
			sess.mu.Unlock()
			return
		}
		sourceIP := extractIPString(remoteAddr)
		if n <= 0 || sourceIP != sess.ExpectedSourceIP {
			continue
		}
		seq, valErr := ValidateUDPPacketPayload(buf[:n], secret, sess.SessionID, sess.Nonce, sess.MaxPackets)
		sess.mu.Lock()
		if valErr != nil {
			sess.InvalidPackets++
			sess.mu.Unlock()
			s.AddLog(fmt.Sprintf("⚠️ [Receiver] Ignored unverified UDP datagram from %s: %v", sourceIP, valErr))
			continue
		}
		if sess.SeenSeq[seq] {
			sess.DuplicateCount++
			sess.mu.Unlock()
			continue
		}
		sess.SeenSeq[seq] = true
		sess.State = RecvRunning
		rec := VerifiedPacketRecord{
			Seq:          seq,
			SourceIP:     sourceIP,
			Protocol:     "udp",
			PayloadBytes: n,
			Timestamp:    time.Now().Format("15:04:05.000"),
		}
		sess.VerifiedPackets = append(sess.VerifiedPackets, rec)
		sess.mu.Unlock()

		s.AddLog(fmt.Sprintf("🎯 [Receiver] VERIFIED UDP Packet #%d from Source IP %s (Session=%s)", seq, sourceIP, sess.SessionID[:8]))
	}
}

func (s *AppServer) runICMPReceiverLoop(ctx context.Context, conn net.PacketConn, sess *ReceiverSession, secret string) {
	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() {
			_ = conn.Close()
		})
	}

	defer func() {
		closeConn()
		sess.Cancel()

		finalServerState := RecvIdle
		sess.mu.Lock()
		if sess.State == RecvReady || sess.State == RecvRunning || sess.State == RecvInitializing {
			sess.State = RecvCompleted
		} else if sess.State == RecvError {
			finalServerState = RecvError
		}
		sess.mu.Unlock()

		s.onSessionExit(sess, finalServerState)
		sess.markDone()
		s.AddLog(fmt.Sprintf("🏁 [Receiver] ICMP session %s closed.", sess.SessionID[:8]))
	}()

	go func() {
		select {
		case <-ctx.Done():
			closeConn()
		case <-sess.DoneChan:
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || sess.IsCancelled() {
				return
			}
			sess.mu.Lock()
			sess.State = RecvError
			sess.LastError = err.Error()
			sess.mu.Unlock()
			return
		}
		sourceIP := extractIPString(addr)
		if n <= 0 || sourceIP != sess.ExpectedSourceIP {
			continue
		}
		seq, icmpID, icmpSeq, valErr := ValidateICMPRawPacket(buf[:n], secret, sess.SessionID, sess.Nonce, sess.MaxPackets)
		if valErr != nil {
			continue
		}
		sess.mu.Lock()
		if sess.SeenSeq[seq] {
			sess.DuplicateCount++
			sess.mu.Unlock()
			continue
		}
		sess.SeenSeq[seq] = true
		sess.State = RecvRunning
		rec := VerifiedPacketRecord{
			Seq:          seq,
			SourceIP:     sourceIP,
			Protocol:     "icmp",
			ICMPID:       icmpID,
			ICMPSeq:      icmpSeq,
			PayloadBytes: n,
			Timestamp:    time.Now().Format("15:04:05.000"),
		}
		sess.VerifiedPackets = append(sess.VerifiedPackets, rec)
		sess.mu.Unlock()

		s.AddLog(fmt.Sprintf("🎯 [Receiver] VERIFIED ICMP Echo Request #%d (ID=%d, ICMPSeq=%d) from Source IP %s", seq, icmpID, icmpSeq, sourceIP))
	}
}

func extractIPString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.IPAddr:
		return a.IP.String()
	default:
		s := addr.String()
		if host, _, err := net.SplitHostPort(s); err == nil {
			return host
		}
		return s
	}
}

func extractRemoteHostIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// Persistent Heartbeat & Connection State Machine

type HeartbeatPayload struct {
	ServerID        string `json:"server_id"`
	PublicIP        string `json:"public_ip"`
	LocalOutboundIP string `json:"local_outbound_ip,omitempty"`
	ListenPort      string `json:"listen_port"`
	ReceiverState   string `json:"receiver_state"`
	ActiveSessionID string `json:"active_session_id"`
}

func (s *AppServer) StartHeartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.performHeartbeatTick()
			}
		}
	}()
}

func (s *AppServer) performHeartbeatTick() {
	s.mu.RLock()
	peer := s.Peer
	localRecv := s.LocalReceiverState
	pubIP := s.PublicIP
	localIP := s.LocalOutboundIP
	listenPort := s.Port
	srvID := s.ServerID
	var activeSessID string
	if s.ActiveRecvSession != nil {
		activeSessID = s.ActiveRecvSession.SessionID
	}
	s.mu.RUnlock()

	if peer == nil {
		return
	}

	reqPayload := HeartbeatPayload{
		ServerID:        srvID,
		PublicIP:        pubIP,
		LocalOutboundIP: localIP,
		ListenPort:      listenPort,
		ReceiverState:   localRecv,
		ActiveSessionID: activeSessID,
	}
	var respPayload HeartbeatPayload
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	err := s.doPeerRequest(ctx, peer, "/api/peer/heartbeat", reqPayload, &respPayload, 2500*time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		s.MissedHeartbeats++
		if s.MissedHeartbeats >= 2 {
			if s.ConnState == ConnConnected {
				s.AddLog(fmt.Sprintf("⚠️ [Monitor] Lost heartbeat with peer %s (%v). Attempting automatic reconnection...", peer.Addr, err))
			}
			s.ConnState = ConnConnecting
			s.PeerReceiverState = RecvIdle
			s.PreparedSession = nil
		}
		return
	}

	wasReconnecting := s.ConnState != ConnConnected
	s.MissedHeartbeats = 0
	s.ConnState = ConnConnected
	s.LastHeartbeat = time.Now()
	s.PeerReceiverState = respPayload.ReceiverState

	if s.PreparedSession != nil {
		if respPayload.ActiveSessionID != s.PreparedSession.SessionID ||
			(respPayload.ReceiverState != RecvReady && respPayload.ReceiverState != RecvRunning) {
			s.PreparedSession = nil
		}
	}

	if wasReconnecting {
		s.AddLog(fmt.Sprintf("✅ [Monitor] Persistent TLS connection restored with peer %s (ID=%s)", peer.Addr, peer.ServerID))
	}
}

// Middleware: Admin Authentication & Peer TLS+HMAC Authentication

func (s *AppServer) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		key := r.Header.Get("X-Admin-Key")
		if key == "" {
			if c, err := r.Cookie("cspf_admin_key"); err == nil {
				key = c.Value
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.AdminKey)) != 1 {
			http.Error(w, "Unauthorized: کلید دسترسی مدیریت نامعتبر است", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *AppServer) requirePeerTLSAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "Forbidden: Peer control channel strictly requires TLS 1.3", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		tsStr := r.Header.Get("X-Timestamp")
		sig := r.Header.Get("X-Peer-Signature")
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid timestamp header", http.StatusUnauthorized)
			return
		}
		diff := time.Since(time.Unix(ts, 0))
		if diff < -60*time.Second || diff > 60*time.Second {
			http.Error(w, "Request timestamp expired", http.StatusUnauthorized)
			return
		}

		expectedLocalSig := signPeerRequest(s.PairingSecret, r.Method, r.URL.Path, tsStr, bodyBytes)
		validSig := subtle.ConstantTimeCompare([]byte(sig), []byte(expectedLocalSig)) == 1

		if !validSig {
			s.mu.RLock()
			peer := s.Peer
			s.mu.RUnlock()
			if peer != nil {
				expectedPeerSig := signPeerRequest(peer.SharedSecret, r.Method, r.URL.Path, tsStr, bodyBytes)
				validSig = subtle.ConstantTimeCompare([]byte(sig), []byte(expectedPeerSig)) == 1
			}
		}

		if !validSig {
			http.Error(w, "Unauthorized: Invalid peer HMAC signature", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Peer Control Plane Endpoints (/api/peer/*)

type PeerPairRequest struct {
	SenderServerID        string `json:"sender_server_id"`
	SenderAddr            string `json:"sender_addr"`
	SenderPublicIP        string `json:"sender_public_ip"`
	SenderLocalOutboundIP string `json:"sender_local_outbound_ip,omitempty"`
	SenderListenPort      string `json:"sender_listen_port,omitempty"`
	SenderCertFingerprint string `json:"sender_cert_fingerprint"`
	SenderSecret          string `json:"sender_secret"`
}

type PeerPairResponse struct {
	ReceiverServerID        string `json:"receiver_server_id"`
	ReceiverPublicIP        string `json:"receiver_public_ip"`
	ReceiverLocalOutboundIP string `json:"receiver_local_outbound_ip,omitempty"`
	ReceiverCertFingerprint string `json:"receiver_cert_fingerprint"`
	ReceiverState           string `json:"receiver_state"`
	ObservedSenderIP        string `json:"observed_sender_ip,omitempty"`
}

func (s *AppServer) handlePeerPair(w http.ResponseWriter, r *http.Request) {
	var req PeerPairRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	if len(req.SenderCertFingerprint) != 64 || len(req.SenderServerID) < 8 {
		http.Error(w, "Invalid peer identity parameters", http.StatusBadRequest)
		return
	}
	if req.SenderPublicIP != "" && req.SenderPublicIP != IPValueUnknown && !isValidIPv4(req.SenderPublicIP) {
		http.Error(w, "Invalid sender_public_ip parameter", http.StatusBadRequest)
		return
	}

	observedIP := extractRemoteHostIP(r.RemoteAddr)

	peerPublicIP := IPValueUnknown
	if IsPublicRoutableIPv4(req.SenderPublicIP) {
		peerPublicIP = req.SenderPublicIP
	} else if IsPublicRoutableIPv4(observedIP) {
		peerPublicIP = observedIP
	}

	peerPort := strings.TrimSpace(req.SenderListenPort)
	if peerPort == "" {
		if _, p, err := net.SplitHostPort(req.SenderAddr); err == nil {
			peerPort = p
		}
	}
	if peerPort == "" {
		peerPort = "8085"
	}

	var peerControlIP string
	if isValidIPv4(peerPublicIP) {
		peerControlIP = peerPublicIP
	} else if isValidIPv4(observedIP) {
		peerControlIP = observedIP
	} else if isValidIPv4(req.SenderLocalOutboundIP) {
		peerControlIP = req.SenderLocalOutboundIP
	} else if host, _, err := net.SplitHostPort(req.SenderAddr); err == nil && isValidIPv4(host) {
		peerControlIP = host
	}

	if !isValidIPv4(peerControlIP) {
		http.Error(w, "Unable to determine valid routable control IPv4 for sender", http.StatusBadRequest)
		return
	}
	peerControlAddr := net.JoinHostPort(peerControlIP, peerPort)

	s.mu.Lock()
	s.Peer = &PeerConfig{
		Addr:            peerControlAddr,
		ControlIP:       peerControlIP,
		ServerID:        req.SenderServerID,
		PublicIP:        peerPublicIP,
		LocalOutboundIP: req.SenderLocalOutboundIP,
		CertFingerprint: strings.ToLower(req.SenderCertFingerprint),
		SharedSecret:    s.PairingSecret,
	}
	s.ConnState = ConnConnected
	s.LastHeartbeat = time.Now()
	s.MissedHeartbeats = 0
	localRecv := s.LocalReceiverState
	myPubIP := s.PublicIP
	myLocalIP := s.LocalOutboundIP
	myCertFP := s.CertFingerprint
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🔐 [Pairing] Paired over TLS 1.3 with peer ID=%s (ControlAddr=%s, PublicIP=%s, LocalIP=%s)",
		req.SenderServerID, peerControlAddr, peerPublicIP, req.SenderLocalOutboundIP))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PeerPairResponse{
		ReceiverServerID:        s.ServerID,
		ReceiverPublicIP:        myPubIP,
		ReceiverLocalOutboundIP: myLocalIP,
		ReceiverCertFingerprint: myCertFP,
		ReceiverState:           localRecv,
		ObservedSenderIP:        observedIP,
	})
}

func (s *AppServer) handlePeerHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.Peer != nil && s.Peer.ServerID == req.ServerID {
		s.ConnState = ConnConnected
		s.LastHeartbeat = time.Now()
		s.MissedHeartbeats = 0
		s.PeerReceiverState = req.ReceiverState
		if IsPublicRoutableIPv4(req.PublicIP) {
			s.Peer.PublicIP = req.PublicIP
		}
		if isValidIPv4(req.LocalOutboundIP) {
			s.Peer.LocalOutboundIP = req.LocalOutboundIP
		}
	}
	localRecv := s.LocalReceiverState
	myPubIP := s.PublicIP
	myLocalIP := s.LocalOutboundIP
	var activeSessID string
	if s.ActiveRecvSession != nil {
		activeSessID = s.ActiveRecvSession.SessionID
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HeartbeatPayload{
		ServerID:        s.ServerID,
		PublicIP:        myPubIP,
		LocalOutboundIP: myLocalIP,
		ListenPort:      s.Port,
		ReceiverState:   localRecv,
		ActiveSessionID: activeSessID,
	})
}

func (s *AppServer) handlePeerPrepare(w http.ResponseWriter, r *http.Request) {
	var req PeerPrepareRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp, err := s.StartReceiverSessionWithContext(r.Context(), req, s.PairingSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type PeerSessionReportRequest struct {
	SessionID   string `json:"session_id"`
	StopSession bool   `json:"stop_session"`
}

type PeerSessionReportResponse struct {
	SessionID       string                 `json:"session_id"`
	State           string                 `json:"state"`
	VerifiedCount   int                    `json:"verified_count"`
	InvalidCount    int                    `json:"invalid_count"`
	DuplicateCount  int                    `json:"duplicate_count"`
	VerifiedPackets []VerifiedPacketRecord `json:"verified_packets"`
	LastError       string                 `json:"last_error,omitempty"`
}

func (s *AppServer) handlePeerResults(w http.ResponseWriter, r *http.Request) {
	var req PeerSessionReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	sess := s.SessionHistory[req.SessionID]
	if sess == nil && s.ActiveRecvSession != nil && s.ActiveRecvSession.SessionID == req.SessionID {
		sess = s.ActiveRecvSession
	}
	s.mu.RUnlock()

	if sess == nil {
		http.Error(w, "Session not found on receiver", http.StatusNotFound)
		return
	}

	if req.StopSession {
		sess.Cancel()
		select {
		case <-sess.DoneChan:
		case <-time.After(3 * time.Second):
		}
	}

	sess.mu.Lock()
	pkts := make([]VerifiedPacketRecord, len(sess.VerifiedPackets))
	copy(pkts, sess.VerifiedPackets)
	resp := PeerSessionReportResponse{
		SessionID:       sess.SessionID,
		State:           sess.State,
		VerifiedCount:   len(sess.VerifiedPackets),
		InvalidCount:    sess.InvalidPackets,
		DuplicateCount:  sess.DuplicateCount,
		VerifiedPackets: pkts,
		LastError:       sess.LastError,
	}
	sess.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Local Operator Admin Endpoints (/api/admin/*)

func (s *AppServer) handleAdminSetPublicIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicIP string `json:"public_ip"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "فرمت JSON نامعتبر است", http.StatusBadRequest)
		return
	}
	if err := s.SetManualPublicIP(req.PublicIP); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	pubIP := s.PublicIP
	pubSrc := s.PublicIPSource
	localIP := s.LocalOutboundIP
	behindNAT := s.BehindNAT
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"public_ip":         pubIP,
		"public_ip_source":  pubSrc,
		"local_outbound_ip": localIP,
		"behind_nat":        behindNAT,
		"pairing_token":     s.PairingToken(),
	})
}

func (s *AppServer) handleAdminPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RemoteToken string `json:"remote_token"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "فرمت JSON نامعتبر است", http.StatusBadRequest)
		return
	}

	peerCfg, err := ParsePairingToken(req.RemoteToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	routeCtx, routeCancel := context.WithTimeout(r.Context(), 2*time.Second)
	routeInfo, routeErr := s.ResolveRoute(routeCtx, peerCfg.ControlIP)
	routeCancel()

	s.mu.Lock()
	s.ConnState = ConnAuthenticating
	s.PreparedSession = nil
	senderLocalIP := s.LocalOutboundIP
	if routeErr == nil && isValidIPv4(routeInfo.SourceIP) {
		senderLocalIP = routeInfo.SourceIP
	}
	senderPubIP := s.PublicIP
	senderCtrlIP := s.effectiveControlIPLocked()
	if !isValidIPv4(senderCtrlIP) && isValidIPv4(senderLocalIP) {
		senderCtrlIP = senderLocalIP
	}
	senderPort := s.Port
	senderCertFP := s.CertFingerprint
	s.mu.Unlock()

	pairReq := PeerPairRequest{
		SenderServerID:        s.ServerID,
		SenderAddr:            fmt.Sprintf("%s:%s", senderCtrlIP, senderPort),
		SenderPublicIP:        senderPubIP,
		SenderLocalOutboundIP: senderLocalIP,
		SenderListenPort:      senderPort,
		SenderCertFingerprint: senderCertFP,
		SenderSecret:          peerCfg.SharedSecret,
	}
	var pairResp PeerPairResponse
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.doPeerRequest(ctx, peerCfg, "/api/peer/pair", pairReq, &pairResp, 5*time.Second); err != nil {
		s.mu.Lock()
		s.ConnState = ConnError
		s.mu.Unlock()
		s.AddLog(fmt.Sprintf("[-] [Pairing] Mutual TLS pairing failed with %s: %v", peerCfg.Addr, err))
		http.Error(w, "خطا در برقراری اتصال امن TLS با سرور مقابل: "+err.Error(), http.StatusBadGateway)
		return
	}

	if IsPublicRoutableIPv4(pairResp.ReceiverPublicIP) {
		peerCfg.PublicIP = pairResp.ReceiverPublicIP
	}
	if isValidIPv4(pairResp.ReceiverLocalOutboundIP) {
		peerCfg.LocalOutboundIP = pairResp.ReceiverLocalOutboundIP
	}

	s.mu.Lock()
	s.Peer = peerCfg
	s.ConnState = ConnConnected
	s.PeerReceiverState = pairResp.ReceiverState
	s.LastHeartbeat = time.Now()
	s.MissedHeartbeats = 0
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("✅ [Pairing] Connected over TLS 1.3 to Peer ID=%s (Control=%s, PeerPublicIP=%s)",
		pairResp.ReceiverServerID, peerCfg.Addr, peerCfg.PublicIP))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "CONNECTED",
		"peer_server_id": pairResp.ReceiverServerID,
		"peer_ip":        peerCfg.TargetIP(),
		"peer_public_ip": peerCfg.PublicIP,
		"receiver_state": pairResp.ReceiverState,
	})
}

func (s *AppServer) handleAdminPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SpoofIP     string `json:"spoof_ip"`
		TestType    string `json:"test_type"`
		PacketCount int    `json:"packet_count"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req.SpoofIP = strings.TrimSpace(req.SpoofIP)
	if !isValidIPv4(req.SpoofIP) {
		http.Error(w, "آدرس IP جعلی (Spoof IP) معتبر نیست", http.StatusBadRequest)
		return
	}
	if req.TestType != "icmp" && req.TestType != "udp" {
		http.Error(w, "متد تست انتخاب‌شده پشتیبانی نمی‌شود", http.StatusBadRequest)
		return
	}
	if req.PacketCount <= 0 || req.PacketCount > 10 {
		req.PacketCount = 3
	}

	s.mu.RLock()
	peer := s.Peer
	connState := s.ConnState
	s.mu.RUnlock()

	if peer == nil || connState != ConnConnected {
		http.Error(w, "ابتدا باید اتصال امن (Pairing) با سرور دوم برقرار شود", http.StatusPreconditionFailed)
		return
	}

	sessionID := randomHex(16)
	nonce := randomHex(16)
	prepReq := PeerPrepareRequest{
		SessionID:        sessionID,
		Nonce:            nonce,
		ExpectedSourceIP: req.SpoofIP,
		TestType:         req.TestType,
		UDPPort:          5555,
		MaxPackets:       req.PacketCount,
		TimeoutSec:       45,
	}

	var prepResp PeerPrepareResponse
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.doPeerRequest(ctx, peer, "/api/peer/prepare", prepReq, &prepResp, 5*time.Second); err != nil {
		s.mu.Lock()
		s.PeerReceiverState = RecvError
		s.PreparedSession = nil
		s.mu.Unlock()
		s.AddLog(fmt.Sprintf("[-] [Prepare] Receiver failed to initialize listener: %v", err))
		http.Error(w, "خطا در آماده‌سازی شنونده روی سرور دوم: "+err.Error(), http.StatusBadGateway)
		return
	}

	if prepResp.ReceiverState != RecvReady {
		http.Error(w, "سرور دوم وضعیت READY_TO_RECEIVE را تایید نکرد", http.StatusBadGateway)
		return
	}

	s.mu.Lock()
	s.PeerReceiverState = RecvReady
	s.PreparedSession = &PreparedSessionInfo{
		SessionID:        sessionID,
		Nonce:            nonce,
		ExpectedSourceIP: req.SpoofIP,
		TestType:         req.TestType,
		UDPPort:          5555,
		PacketCount:      req.PacketCount,
	}
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🟢 [Handshake] Receiver confirmed READY_TO_RECEIVE on %s (Session=%s)", prepResp.BoundAddress, sessionID[:8]))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id":     sessionID,
		"receiver_state": prepResp.ReceiverState,
		"bound_address":  prepResp.BoundAddress,
	})
}

// AdminTestResult explicitly separates receiver readiness, SNAT rule installation,
// local packet generation, local rule counter matching, and genuine remote spoof reception.
type AdminTestResult struct {
	SessionID             string                 `json:"session_id"`
	PrimaryClassification string                 `json:"primary_classification"`
	Classifications       []string               `json:"classifications"`
	ReceiverListenerReady bool                   `json:"receiver_listener_ready"`
	SNATRuleInstalled     bool                   `json:"snat_rule_installed"`
	LocalPacketGenSuccess bool                   `json:"local_packet_gen_success"`
	RemoteSpoofVerified   bool                   `json:"remote_spoof_verified"`
	IsLoopbackOrSimulated bool                   `json:"is_loopback_or_simulated"`
	PacketsAttempted      int                    `json:"packets_attempted"`
	PacketsSent           int                    `json:"packets_sent"`
	SNATPacketsMatched    int                    `json:"snat_packets_matched"`
	SNATBytesMatched      int                    `json:"snat_bytes_matched"`
	RemoteVerifiedCount   int                    `json:"remote_verified_count"`
	RemoteInvalidCount    int                    `json:"remote_invalid_count"`
	RemoteDuplicateCount  int                    `json:"remote_duplicate_count"`
	VerifiedPackets       []VerifiedPacketRecord `json:"verified_packets"`
	OutgoingInterface     string                 `json:"outgoing_interface"`
	OutgoingSourceIP      string                 `json:"outgoing_source_ip"`
	IsolatedChainName     string                 `json:"isolated_chain_name"`
	StatusClass           string                 `json:"status_class"`
	ResultTitle           string                 `json:"result_title"`
	ConfirmedEvidence     string                 `json:"confirmed_evidence"`
	PossibleExplanations  string                 `json:"possible_explanations"`
}

func (s *AppServer) handleAdminTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if s.ActiveTestRunning {
		s.mu.Unlock()
		http.Error(w, "یک تست در حال حاضر در حال اجراست؛ لطفاً تا پایان آن صبر کنید", http.StatusConflict)
		return
	}
	peer := s.Peer
	connState := s.ConnState
	prep := s.PreparedSession
	if peer == nil || connState != ConnConnected || prep == nil || s.PeerReceiverState != RecvReady {
		s.mu.Unlock()
		http.Error(w, "گیرنده در وضعیت READY_TO_RECEIVE نیست. ابتدا دکمه «آماده‌سازی گیرنده» را بزنید.", http.StatusPreconditionFailed)
		return
	}
	s.ActiveTestRunning = true
	s.PeerReceiverState = RecvRunning
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.ActiveTestRunning = false
		s.PreparedSession = nil
		if s.PeerReceiverState == RecvRunning {
			s.PeerReceiverState = RecvCompleted
		}
		s.mu.Unlock()
	}()

	result := s.executeCoordinatedTest(r.Context(), peer, prep)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *AppServer) isGenuineNetworkSpoofSetup(targetIP, spoofIP string, routeSrcIP ...string) (bool, string) {
	if s.Runner == nil || s.Runner.IsMock() {
		return false, "mocked CommandRunner is in use (iptables SNAT not applied to real kernel netfilter)"
	}
	tIP := net.ParseIP(strings.TrimSpace(targetIP))
	spIP := net.ParseIP(strings.TrimSpace(spoofIP))

	s.mu.RLock()
	srvIP := net.ParseIP(strings.TrimSpace(s.ServerIP))
	pubIP := net.ParseIP(strings.TrimSpace(s.PublicIP))
	localIP := net.ParseIP(strings.TrimSpace(s.LocalOutboundIP))
	s.mu.RUnlock()

	if tIP == nil || spIP == nil {
		return false, "invalid target or spoof IPv4 address"
	}
	if tIP.IsLoopback() || spIP.IsLoopback() || (srvIP != nil && srvIP.IsLoopback()) {
		return false, fmt.Sprintf("loopback address detected (sender=%s, target=%s, spoof=%s); loopback traffic bypasses physical NICs and upstream routers", s.ServerIP, targetIP, spoofIP)
	}
	if pubIP != nil && spIP.Equal(pubIP) {
		return false, fmt.Sprintf("spoof_ip (%s) is identical to sender's public IP (%s); no source IP spoofing occurred", spoofIP, pubIP.String())
	}
	if localIP != nil && spIP.Equal(localIP) {
		return false, fmt.Sprintf("spoof_ip (%s) is identical to sender's local outbound IP (%s); no source IP spoofing occurred", spoofIP, localIP.String())
	}
	if srvIP != nil && spIP.Equal(srvIP) {
		return false, fmt.Sprintf("spoof_ip (%s) is identical to sender's own IP (%s); no source IP spoofing occurred", spoofIP, srvIP.String())
	}
	for _, rSrc := range routeSrcIP {
		if rIP := net.ParseIP(strings.TrimSpace(rSrc)); rIP != nil {
			if rIP.IsLoopback() {
				return false, fmt.Sprintf("route source IP (%s) is loopback", rSrc)
			}
			if spIP.Equal(rIP) {
				return false, fmt.Sprintf("spoof_ip (%s) is identical to outgoing route source IP (%s)", spoofIP, rSrc)
			}
		}
	}
	return true, ""
}

func (s *AppServer) executeCoordinatedTest(ctx context.Context, peer *PeerConfig, prep *PreparedSessionInfo) AdminTestResult {
	targetIP := peer.TargetIP()
	res := AdminTestResult{
		SessionID:             prep.SessionID,
		PacketsAttempted:      prep.PacketCount,
		ReceiverListenerReady: true,
		Classifications:       []string{ClassReceiverListenerReady},
	}

	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var dummy PeerSessionReportResponse
		_ = s.doPeerRequest(stopCtx, peer, "/api/peer/results", PeerSessionReportRequest{
			SessionID:   prep.SessionID,
			StopSession: true,
		}, &dummy, 3*time.Second)
	}()

	// Stage 1: Route, Outgoing Interface, and Local Source IP Resolution via `ip route get TARGET_IP`
	routeInfo, err := s.ResolveRoute(ctx, targetIP)
	if err != nil {
		s.AddLog(fmt.Sprintf("[-] [Routing] %v", err))
		res.PrimaryClassification = ClassRoutingError
		res.Classifications = append(res.Classifications, ClassRoutingError)
		res.StatusClass = "failure"
		res.ResultTitle = "❌ خطای مسیریابی (ROUTING_ERROR)"
		res.ConfirmedEvidence = fmt.Sprintf("مسیریابی کرنل برای مقصد %s شکست خورد: %v", targetIP, err)
		res.PossibleExplanations = "جدول مسیریابی سرور (ip route) مسیر معتبری به سمت سرور دوم ندارد."
		return res
	}
	iface := routeInfo.Interface
	res.OutgoingInterface = iface
	res.OutgoingSourceIP = routeInfo.SourceIP

	// Stage 2: Isolated Per-Process/Per-Session iptables SNAT Chain Installation
	shortID := prep.SessionID[:8]
	chainIso, err := s.SetupIsolatedSNATChain(ctx, shortID, iface, targetIP, prep.ExpectedSourceIP, prep.TestType, prep.UDPPort)
	if err != nil {
		s.AddLog(fmt.Sprintf("[-] [Firewall] %v", err))
		res.PrimaryClassification = ClassPermissionError
		res.Classifications = append(res.Classifications, ClassPermissionError)
		res.StatusClass = "failure"
		res.ResultTitle = "❌ خطای دسترسی یا نصب فایروال محلی (LOCAL_PERMISSION_ERROR)"
		res.ConfirmedEvidence = fmt.Sprintf("ایجاد زنجیره ایزوله iptables شکست خورد: %v", err)
		res.PossibleExplanations = "برنامه بدون دسترسی root / CAP_NET_ADMIN اجرا شده یا ماژول nat کرنل فعال نیست."
		return res
	}
	defer chainIso.Cleanup()
	res.SNATRuleInstalled = true
	res.IsolatedChainName = chainIso.ChainName
	res.Classifications = append(res.Classifications, ClassSNATRuleInstalled)
	s.AddLog(fmt.Sprintf("[Sender] Installed isolated SNAT chain %s on interface %s (local src %s -> spoof to:%s)",
		chainIso.ChainName, iface, routeInfo.SourceIP, prep.ExpectedSourceIP))

	// Stage 3: Local Packet Generation
	packetsSent := 0
	var sendExecErr error

	if prep.TestType == "udp" {
		raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", targetIP, prep.UDPPort))
		if err != nil {
			sendExecErr = err
		} else {
			conn, err := net.DialUDP("udp4", nil, raddr)
			if err != nil {
				sendExecErr = err
			} else {
				for seq := 1; seq <= prep.PacketCount; seq++ {
					payload := BuildUDPPacketPayload(peer.SharedSecret, prep.SessionID, prep.Nonce, seq, time.Now().UnixMilli())
					n, wErr := conn.Write(payload)
					if wErr != nil {
						sendExecErr = wErr
						s.AddLog(fmt.Sprintf("[-] [Sender] UDP write error on seq #%d: %v", seq, wErr))
						break
					}
					if n == len(payload) {
						packetsSent++
					}
					time.Sleep(250 * time.Millisecond)
				}
				_ = conn.Close()
			}
		}
	} else {
		for seq := 1; seq <= prep.PacketCount; seq++ {
			patHex, pErr := BuildICMPPatternHex(peer.SharedSecret, prep.SessionID, prep.Nonce, seq)
			if pErr != nil {
				sendExecErr = pErr
				break
			}
			pingCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			out, exitCode, runErr := s.Runner.Run(pingCtx, "ping", "-c", "1", "-W", "1", "-s", "48", "-p", patHex, targetIP)
			cancel()

			outStr := string(out)
			if strings.Contains(outStr, "1 packets transmitted") || strings.Contains(outStr, "1عملیات") || exitCode == 0 || (exitCode == 1 && strings.Contains(outStr, "transmitted")) {
				packetsSent++
			} else {
				sendExecErr = fmt.Errorf("ping exit=%d: %s (%v)", exitCode, strings.TrimSpace(outStr), runErr)
				s.AddLog(fmt.Sprintf("[-] [Sender] ICMP seq #%d execution failure: %v", seq, sendExecErr))
				if strings.Contains(strings.ToLower(outStr), "operation not permitted") || strings.Contains(strings.ToLower(outStr), "permission denied") {
					res.PrimaryClassification = ClassPermissionError
					res.Classifications = append(res.Classifications, ClassPermissionError)
					res.StatusClass = "failure"
					res.ResultTitle = "❌ خطای سطح دسترسی (LOCAL_PERMISSION_ERROR)"
					res.ConfirmedEvidence = fmt.Sprintf("ارسال پکت ICMP توسط سیستم‌عامل رد شد: %s", strings.TrimSpace(outStr))
					res.PossibleExplanations = "دسترسی CAP_NET_RAW یا مجوز اجرای ping وجود ندارد یا یک قانون فایروال OUTPUT ارسال را مسدود کرده است."
					return res
				}
			}
		}
	}

	res.PacketsSent = packetsSent
	if packetsSent > 0 {
		res.LocalPacketGenSuccess = true
		res.Classifications = append(res.Classifications, ClassLocalGenSuccess)
		s.AddLog(fmt.Sprintf("[Sender] Local packet generation: %d/%d packets written to socket.", packetsSent, prep.PacketCount))
	}

	// Stage 4: Local SNAT Rule Counter Inspection
	snatPkts, snatBytes, _, counterErr := chainIso.ReadCounters(ctx)
	if counterErr == nil {
		res.SNATPacketsMatched = snatPkts
		res.SNATBytesMatched = snatBytes
		if snatPkts > 0 {
			res.Classifications = append(res.Classifications, ClassLocalRuleMatched)
			s.AddLog(fmt.Sprintf("[Sender] Isolated chain %s matched %d packets (%d bytes).", chainIso.ChainName, snatPkts, snatBytes))
		}
	}

	time.Sleep(450 * time.Millisecond)

	// Stage 5: Remote Receiver Packet Reception & Source IP Verification
	var remoteReport PeerSessionReportResponse
	repCtx, repCancel := context.WithTimeout(ctx, 5*time.Second)
	defer repCancel()
	repErr := s.doPeerRequest(repCtx, peer, "/api/peer/results", PeerSessionReportRequest{
		SessionID:   prep.SessionID,
		StopSession: true,
	}, &remoteReport, 5*time.Second)

	if repErr != nil {
		s.AddLog(fmt.Sprintf("[-] [Verification] Failed to retrieve report from receiver: %v", repErr))
		res.PrimaryClassification = ClassReceiverUnavailable
		res.Classifications = append(res.Classifications, ClassReceiverUnavailable, ClassTestIncomplete)
		res.StatusClass = "warning"
		res.ResultTitle = "⚠️ عدم دسترسی به گیرنده در زمان دریافت گزارش (RECEIVER_UNAVAILABLE)"
		res.ConfirmedEvidence = fmt.Sprintf("تعداد %d پکت در مبدا تولید شد و %d پکت با زنجیره SNAT (%s) تطابق یافت، اما دریافت گزارش از سرور دوم با خطا مواجه شد: %v", packetsSent, snatPkts, chainIso.ChainName, repErr)
		res.PossibleExplanations = "ارتباط کنترلی TLS با سرور دوم حین تست قطع شد؛ بنابراین تایید یا رد تحویل پکت‌ها امکان‌پذیر نیست."
		return res
	}

	matchingSpoofSourceCount := 0
	for _, vp := range remoteReport.VerifiedPackets {
		if vp.SourceIP == prep.ExpectedSourceIP {
			matchingSpoofSourceCount++
		}
	}

	res.RemoteVerifiedCount = matchingSpoofSourceCount
	res.RemoteInvalidCount = remoteReport.InvalidCount
	res.RemoteDuplicateCount = remoteReport.DuplicateCount
	res.VerifiedPackets = remoteReport.VerifiedPackets

	if packetsSent == 0 {
		res.PrimaryClassification = ClassTestIncomplete
		res.Classifications = append(res.Classifications, ClassTestIncomplete)
		res.StatusClass = "failure"
		res.ResultTitle = "❌ خطا در تولید پکت محلی (TEST_INCOMPLETE)"
		res.ConfirmedEvidence = fmt.Sprintf("هیچ پکتی (0/%d) توسط سوکت یا ابزار محلی ارسال نشد: %v", prep.PacketCount, sendExecErr)
		res.PossibleExplanations = "خطای سوکت محلی، محدودیت فایروال OUTPUT یا خطای ابزار شبکه."
		return res
	}

	if matchingSpoofSourceCount > 0 {
		genuineNet, simReason := s.isGenuineNetworkSpoofSetup(targetIP, prep.ExpectedSourceIP, routeInfo.SourceIP)
		if !genuineNet {
			res.IsLoopbackOrSimulated = true
			res.RemoteSpoofVerified = false
			res.PrimaryClassification = ClassSimulatedControlVerified
			res.Classifications = append(res.Classifications, ClassSimulatedControlVerified)
			res.StatusClass = "warning"
			res.ResultTitle = "⚠️ تست کنترلی/لوپ‌بک انجام شد — اثبات‌کننده IP Spoofing واقعی نیست (SIMULATED_CONTROL_FLOW_VERIFIED)"
			res.ConfirmedEvidence = fmt.Sprintf("گیرنده %d پکت با امضای معتبر دریافت کرد، اما این تست به دلیل [%s] به عنوان SPOOF_SUCCESS ثبت نمی‌شود.", matchingSpoofSourceCount, simReason)
			res.PossibleExplanations = "تست روی 127.0.0.1، فایروال شبیه‌سازی‌شده (Mock) یا IP یکسان با مبدا صرفاً صحت کانال کنترلی و فریم‌بندی پکت‌ها را می‌سنجد و عبور پکت اسپوف‌شده از کارت شبکه و روترهای واقعی را اثبات نمی‌کند."
			return res
		}

		res.RemoteSpoofVerified = true
		res.PrimaryClassification = ClassSpoofSuccess
		res.Classifications = append(res.Classifications, ClassSpoofSuccess)
		res.StatusClass = "success"
		res.ResultTitle = "✅ تایید قطعی IP Spoofing در سرور دوم (SPOOF_SUCCESS)"
		res.ConfirmedEvidence = fmt.Sprintf("شواهد تفکیک‌شده: ۱) شنونده مقصد آماده بود، ۲) زنجیره SNAT (%s) روی اینترفیس %s (آدرس محلی %s) نصب شد، ۳) %d پکت در مبدا تولید شد، ۴) %d پکت در کرنل تغییر مبدا یافت و ۵) سرور دوم (%s) دقیقاً %d پکت رمزنگاری‌شده با آدرس مبدا اسپوف‌شده (%s) دریافت و تایید کرد.",
			chainIso.ChainName, iface, routeInfo.SourceIP, packetsSent, snatPkts, targetIP, matchingSpoofSourceCount, prep.ExpectedSourceIP)
		res.PossibleExplanations = "شبکه مبدا و مسیر بین دو سرور، پکت‌های دارای آدرس مبدا جعلی (Spoofed Source IP) را مسدود نکرده‌اند."
		return res
	}

	res.RemoteSpoofVerified = false
	res.PrimaryClassification = ClassRemoteNotReceived
	res.Classifications = append(res.Classifications, ClassRemoteNotReceived)
	res.StatusClass = "failure"
	res.ResultTitle = "❌ عدم دریافت پکت اسپوف‌شده در سرور دوم (REMOTE_PACKET_NOT_RECEIVED)"
	res.ConfirmedEvidence = fmt.Sprintf("شواهد تفکیک‌شده: ۱) شنونده مقصد آماده بود، ۲) زنجیره SNAT (%s) روی %s (آدرس محلی %s) نصب شد، ۳) %d پکت در مبدا تولید شد و ۴) %d پکت (%d بایت) با قانون SNAT محلی تطابق یافت؛ اما ۵) سرور دوم ۰ پکت با آدرس اسپوف‌شده (%s) دریافت کرد. (نصب قانون یا افزایش شمارنده SNAT به تنهایی دلیل موفقیت اسپوفینگ نیست.)",
		chainIso.ChainName, iface, routeInfo.SourceIP, packetsSent, snatPkts, snatBytes, prep.ExpectedSourceIP)
	res.PossibleExplanations = "دلایل محتمل: ۱) فیلترینگ مبدا در روتر بالادست یا دیتاسنتر فرستنده (BCP 38 / uRPF) یا NAT بالادست، ۲) مسدود شدن در فایروال مسیر یا سرور مقصد، ۳) عدم تطابق مسیر خروجی یا از دست رفتن پکت در شبکه."
	return res
}

// RunRealVPSIntegrationTest executes a complete two-server spoofing verification test
// against a paired remote Linux VPS.
func (s *AppServer) RunRealVPSIntegrationTest(ctx context.Context, peerToken, spoofIP, testMethod string, packetCount int) (AdminTestResult, error) {
	peerCfg, err := ParsePairingToken(peerToken)
	if err != nil {
		return AdminTestResult{}, fmt.Errorf("invalid peer token: %w", err)
	}
	if !isValidIPv4(spoofIP) {
		return AdminTestResult{}, fmt.Errorf("invalid spoof IPv4 address: %s", spoofIP)
	}
	if testMethod != "udp" && testMethod != "icmp" {
		return AdminTestResult{}, fmt.Errorf("unsupported test method %q (use udp or icmp)", testMethod)
	}
	if packetCount <= 0 || packetCount > 10 {
		packetCount = 3
	}

	routeInfo, routeErr := s.ResolveRoute(ctx, peerCfg.ControlIP)

	s.mu.RLock()
	senderLocalIP := s.LocalOutboundIP
	if routeErr == nil && isValidIPv4(routeInfo.SourceIP) {
		senderLocalIP = routeInfo.SourceIP
	}
	senderPubIP := s.PublicIP
	senderCtrlIP := s.effectiveControlIPLocked()
	if !isValidIPv4(senderCtrlIP) && isValidIPv4(senderLocalIP) {
		senderCtrlIP = senderLocalIP
	}
	senderPort := s.Port
	senderCertFP := s.CertFingerprint
	s.mu.RUnlock()

	pairReq := PeerPairRequest{
		SenderServerID:        s.ServerID,
		SenderAddr:            fmt.Sprintf("%s:%s", senderCtrlIP, senderPort),
		SenderPublicIP:        senderPubIP,
		SenderLocalOutboundIP: senderLocalIP,
		SenderListenPort:      senderPort,
		SenderCertFingerprint: senderCertFP,
		SenderSecret:          peerCfg.SharedSecret,
	}
	var pairResp PeerPairResponse
	if err := s.doPeerRequest(ctx, peerCfg, "/api/peer/pair", pairReq, &pairResp, 5*time.Second); err != nil {
		return AdminTestResult{}, fmt.Errorf("phase 1 TLS pairing failed: %w", err)
	}
	if IsPublicRoutableIPv4(pairResp.ReceiverPublicIP) {
		peerCfg.PublicIP = pairResp.ReceiverPublicIP
	}

	s.mu.Lock()
	s.Peer = peerCfg
	s.ConnState = ConnConnected
	s.PeerReceiverState = pairResp.ReceiverState
	s.LastHeartbeat = time.Now()
	s.mu.Unlock()

	sessionID := randomHex(16)
	nonce := randomHex(16)
	prepReq := PeerPrepareRequest{
		SessionID:        sessionID,
		Nonce:            nonce,
		ExpectedSourceIP: spoofIP,
		TestType:         testMethod,
		UDPPort:          5555,
		MaxPackets:       packetCount,
		TimeoutSec:       45,
	}
	var prepResp PeerPrepareResponse
	if err := s.doPeerRequest(ctx, peerCfg, "/api/peer/prepare", prepReq, &prepResp, 5*time.Second); err != nil {
		return AdminTestResult{}, fmt.Errorf("phase 2 receiver preparation failed: %w", err)
	}
	if prepResp.ReceiverState != RecvReady {
		return AdminTestResult{}, fmt.Errorf("receiver did not report READY_TO_RECEIVE (got %s)", prepResp.ReceiverState)
	}

	prepInfo := &PreparedSessionInfo{
		SessionID:        sessionID,
		Nonce:            nonce,
		ExpectedSourceIP: spoofIP,
		TestType:         testMethod,
		UDPPort:          5555,
		PacketCount:      packetCount,
	}

	result := s.executeCoordinatedTest(ctx, peerCfg, prepInfo)
	return result, nil
}

func (s *AppServer) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	peerAddr := "—"
	peerID := "—"
	peerIP := "—"
	peerPubIP := IPValueUnknown
	if s.Peer != nil {
		peerAddr = s.Peer.Addr
		peerID = s.Peer.ServerID
		peerIP = s.Peer.TargetIP()
		peerPubIP = s.Peer.PublicIP
	}
	lastHB := "—"
	if !s.LastHeartbeat.IsZero() {
		lastHB = s.LastHeartbeat.Format("15:04:05")
	}
	var prepSessID string
	if s.PreparedSession != nil {
		prepSessID = s.PreparedSession.SessionID
	}
	resp := map[string]interface{}{
		"server_id":            s.ServerID,
		"server_ip":            s.effectiveControlIPLocked(),
		"local_outbound_ip":    s.LocalOutboundIP,
		"local_interface":      s.LocalInterface,
		"public_ip":            s.PublicIP,
		"public_ip_source":     s.PublicIPSource,
		"behind_nat":           s.BehindNAT,
		"port":                 s.Port,
		"conn_state":           s.ConnState,
		"local_receiver_state": s.LocalReceiverState,
		"peer_receiver_state":  s.PeerReceiverState,
		"peer_addr":            peerAddr,
		"peer_id":              peerID,
		"peer_ip":              peerIP,
		"peer_public_ip":       peerPubIP,
		"last_heartbeat":       lastHB,
		"prepared_session_id":  prepSessID,
	}
	s.mu.RUnlock()

	s.logsMu.Lock()
	logsCopy := make([]string, len(s.LiveLogs))
	copy(logsCopy, s.LiveLogs)
	s.logsMu.Unlock()
	resp["logs"] = logsCopy

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *AppServer) handleAdminClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.logsMu.Lock()
	s.LiveLogs = nil
	s.logsMu.Unlock()
	s.AddLog("Logs cleared by operator.")
	w.WriteHeader(http.StatusOK)
}

// Dashboard HTML Template & UI Handler

type DashboardData struct {
	ServerID        string
	LocalOutboundIP string
	PublicIP        string
	PublicIPSource  string
	BehindNAT       bool
	Port            string
	Iface           string
	CertFingerprint string
	PairingToken    string
	AdminKey        string
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CheckSpoof — سامانه مهندسی تشخیص IP Spoofing</title>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <style>
        :root {
            --bg-dark: #070b14;
            --bg-card: rgba(15, 23, 42, 0.9);
            --bg-input: #090e1a;
            --border: #1e293b;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --primary-grad: linear-gradient(135deg, #0284c7 0%, #2563eb 100%);
            --emerald-grad: linear-gradient(135deg, #059669 0%, #10b981 100%);
            --amber-grad: linear-gradient(135deg, #d97706 0%, #f59e0b 100%);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success-bg: rgba(20, 83, 45, 0.45);
            --success-border: #22c55e;
            --success-fg: #4ade80;
            --warning-bg: rgba(113, 63, 18, 0.45);
            --warning-border: #eab308;
            --warning-fg: #facc15;
            --danger-bg: rgba(127, 29, 29, 0.45);
            --danger-border: #ef4444;
            --danger-fg: #f87171;
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg-dark);
            background-image: radial-gradient(at 0% 0%, rgba(14, 165, 233, 0.12) 0px, transparent 50%),
                              radial-gradient(at 100% 100%, rgba(37, 99, 235, 0.1) 0px, transparent 50%);
            color: var(--text-main);
            font-family: 'Vazirmatn', system-ui, -apple-system, sans-serif;
            margin: 0; padding: 20px 14px; min-height: 100vh;
        }
        .wrapper { max-width: 1220px; margin: 0 auto; }
        .navbar {
            display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
            padding: 16px 22px; margin-bottom: 16px; gap: 12px;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand-icon {
            width: 42px; height: 42px; border-radius: 11px; background: var(--primary-grad);
            display: flex; align-items: center; justify-content: center; font-size: 20px;
        }
        .brand-text h1 { margin: 0; font-size: 19px; font-weight: 800; color: #fff; }
        .brand-text p { margin: 2px 0 0 0; font-size: 11.5px; color: var(--text-muted); }
        .nav-pills { display: flex; flex-wrap: wrap; gap: 8px; }
        .pill {
            background: var(--bg-input); border: 1px solid var(--border); padding: 6px 12px;
            border-radius: 999px; font-size: 11.5px; color: var(--text-muted);
            display: flex; align-items: center; gap: 6px;
        }
        .pill strong { color: var(--accent); font-family: monospace; font-size: 12px; }
        .token-banner {
            background: linear-gradient(90deg, rgba(15, 23, 42, 0.95) 0%, rgba(2, 132, 199, 0.1) 100%);
            border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 14px;
            padding: 12px 18px; margin-bottom: 18px; display: flex; flex-wrap: wrap;
            justify-content: space-between; align-items: center; gap: 10px;
        }
        .token-value-wrap {
            display: flex; align-items: center; gap: 8px; background: #050811;
            padding: 7px 12px; border-radius: 10px; border: 1px solid var(--border);
            direction: ltr; flex: 1; max-width: 650px; justify-content: space-between;
        }
        .token-value-wrap code { color: #4ade80; font-family: monospace; font-size: 12px; word-break: break-all; }
        .btn-sm {
            background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 5px 10px;
            border-radius: 6px; font-family: inherit; font-size: 11.5px; cursor: pointer; white-space: nowrap;
        }
        .btn-sm:hover { border-color: var(--accent); }
        .dashboard-grid { display: grid; grid-template-columns: 1.05fr 1.15fr; gap: 18px; }
        @media (max-width: 960px) { .dashboard-grid { grid-template-columns: 1fr; } }
        .card {
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
            padding: 20px; display: flex; flex-direction: column; gap: 14px;
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
        .card-title { margin: 0; font-size: 15px; font-weight: 700; color: #fff; }
        .form-group { display: flex; flex-direction: column; gap: 5px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        label { font-size: 12px; color: var(--text-muted); }
        input, select {
            width: 100%; padding: 10px 12px; background: var(--bg-input); border: 1px solid var(--border);
            color: #fff; border-radius: 9px; font-family: inherit; font-size: 13px; outline: none;
        }
        input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
        .ltr-input { direction: ltr; text-align: left; font-family: monospace; }
        .connect-group { display: flex; gap: 8px; }
        .btn-connect {
            background: var(--emerald-grad); color: #fff; border: none; padding: 0 16px;
            border-radius: 9px; font-family: inherit; font-size: 12.5px; font-weight: 700; cursor: pointer; white-space: nowrap;
        }
        .action-row { display: grid; grid-template-columns: 1fr 1.2fr; gap: 10px; margin-top: 4px; }
        .btn-prepare {
            background: var(--amber-grad); color: #fff; border: none; padding: 13px 14px;
            border-radius: 10px; font-family: inherit; font-size: 13.5px; font-weight: 700; cursor: pointer;
        }
        .btn-primary {
            background: var(--primary-grad); color: #fff; border: none; padding: 13px 14px;
            border-radius: 10px; font-family: inherit; font-size: 13.5px; font-weight: 700; cursor: pointer;
        }
        .btn-prepare:disabled, .btn-primary:disabled {
            background: #1e293b; color: #64748b; cursor: not-allowed; border: 1px solid #334155;
        }
        .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 2px; }
        .chip {
            background: #131c31; border: 1px solid var(--border); color: #cbd5e1;
            padding: 4px 10px; border-radius: 7px; font-size: 11px; cursor: pointer; font-family: monospace;
        }
        .chip:hover { border-color: var(--accent); color: var(--accent); }
        .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
        .metric-box { background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px; padding: 10px; text-align: center; }
        .metric-box .m-title { font-size: 10.5px; color: var(--text-muted); margin-bottom: 3px; }
        .metric-box .m-val { font-size: 13px; font-weight: 800; font-family: monospace; color: #fff; }
        .alert-box { padding: 12px 14px; border-radius: 10px; font-size: 12.5px; line-height: 1.65; display: none; }
        .alert-box.show { display: block; }
        .alert-box strong { display: block; font-size: 13.5px; margin-bottom: 4px; }
        .alert-box.success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success-fg); }
        .alert-box.warning { background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning-fg); }
        .alert-box.failure { background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger-fg); }
        .terminal-window { background: #03060c; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; display: flex; flex-direction: column; flex: 1; min-height: 340px; }
        .terminal-bar { background: #0b1324; padding: 8px 14px; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; direction: ltr; }
        #terminal { padding: 14px; color: #34d399; font-family: monospace; font-size: 12px; line-height: 1.6; overflow-y: auto; flex: 1; max-height: 380px; white-space: pre-wrap; direction: ltr; text-align: left; }
    </style>
</head>
<body>
    <div class="wrapper">
        <header class="navbar">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div class="brand-text">
                    <h1>CheckSpoof Enterprise v2</h1>
                    <p>سامانه مهندسی تشخیص IP Spoofing با تفکیک آدرس محلی (ip route) از آدرس عمومی (Public IP)</p>
                </div>
            </div>
            <div class="nav-pills">
                <div class="pill"><span>شناسه:</span><strong>{{.ServerID}}</strong></div>
                <div class="pill"><span>IP محلی ({{.Iface}}):</span><strong id="local_ip_badge">{{.LocalOutboundIP}}</strong></div>
                <div class="pill"><span>IP عمومی:</span><strong id="public_ip_badge">{{.PublicIP}} ({{.PublicIPSource}})</strong></div>
                <div class="pill"><span>وضعیت اتصال:</span><strong id="conn_state_badge">DISCONNECTED</strong></div>
                <div class="pill"><span>آمادگی گیرنده:</span><strong id="recv_state_badge">IDLE</strong></div>
                <div class="pill"><span>آخرین ضربان:</span><strong id="hb_badge">—</strong></div>
            </div>
        </header>

        <div class="token-banner">
            <div style="font-size: 12.5px;">
                🔑 <strong>توکن جفت‌سازی امن این سرور (حاوی اثرانگشت گواهی TLS):</strong>
            </div>
            <div class="token-value-wrap">
                <code id="my_token" data-token="{{.PairingToken}}">••••••••••••••••••••••••••••••••••••••••••••••••••••</code>
                <div style="display:flex; gap:6px;">
                    <button class="btn-sm" onclick="toggleToken()" id="toggle_btn">نمایش</button>
                    <button class="btn-sm" onclick="copyToken()" id="copy_btn">کپی توکن</button>
                </div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">⚙️ ۱. تنظیمات شبکه، جفت‌سازی TLS 1.3 و آماده‌سازی گیرنده</h2>
                </div>

                <div class="form-group">
                    <label>🌐 تنظیم دستی IP عمومی این سرور (اختیاری — در صورت قرارگیری پشت NAT یا UNKNOWN بودن):</label>
                    <div class="connect-group">
                        <input type="text" id="manual_public_ip" class="ltr-input" placeholder="مثال: 203.0.113.50">
                        <button class="btn-sm" onclick="savePublicIP()">ثبت IP عمومی</button>
                    </div>
                </div>

                <div class="form-group">
                    <label>🔗 توکن سرور دوم (گیرنده):</label>
                    <div class="connect-group">
                        <input type="password" id="remote_token" class="ltr-input" placeholder="IP:PORT|SERVER_ID|CERT_FP|SECRET">
                        <button class="btn-connect" onclick="pairServer()" id="pair_btn">اتصال و احراز هویت TLS</button>
                    </div>
                    <div id="pair_alert" class="alert-box"></div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>🛠️ متد تست پروتکل:</label>
                        <select id="test_type" onchange="invalidatePrepare()">
                            <option value="icmp">Method 1 — ICMP SNAT (امضای رمزنگاری در پکت)</option>
                            <option value="udp">Method 2 — UDP SNAT (فریم رمزنگاری CSPFv2)</option>
                            <option value="raw" disabled>Method 3 — Raw IP Header (NOT IMPLEMENTED)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>🔢 تعداد پکت‌های تست (۱ تا ۱۰):</label>
                        <input type="number" id="packet_count" class="ltr-input" value="3" min="1" max="10" onchange="invalidatePrepare()">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>🎯 سرور مقصد (فقط سرور جفت‌شده مجاز است):</label>
                        <input type="text" id="target_ip" class="ltr-input" readonly placeholder="پس از اتصال خودکار پر می‌شود">
                    </div>
                    <div class="form-group">
                        <label>🎭 آدرس IP جعلی (Spoofed Source IP):</label>
                        <input type="text" id="spoof_ip" class="ltr-input" value="8.8.8.8" oninput="invalidatePrepare()">
                    </div>
                </div>

                <div class="chips">
                    <span class="chip" onclick="setSpoof('8.8.8.8')">Google DNS (8.8.8.8)</span>
                    <span class="chip" onclick="setSpoof('1.1.1.1')">Cloudflare (1.1.1.1)</span>
                    <span class="chip" onclick="setSpoof('9.9.9.9')">Quad9 (9.9.9.9)</span>
                </div>

                <div class="action-row">
                    <button id="prep_btn" class="btn-prepare" disabled onclick="prepareReceiver()">
                        ۱. آماده‌سازی شنونده گیرنده
                    </button>
                    <button id="run_btn" class="btn-primary" disabled onclick="runTest()">
                        ۲. شروع تست و ارزیابی
                    </button>
                </div>

                <div id="test_result_box" class="alert-box"></div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">📊 ۲. مراحل تفکیک‌شده اعتبارسنجی</h2>
                    <span id="local_recv_badge" style="font-size:11.5px; color:var(--text-muted); font-family:monospace;">Local Receiver: IDLE</span>
                </div>

                <div class="metrics-grid">
                    <div class="metric-box">
                        <div class="m-title">۱. تولید پکت محلی</div>
                        <div class="m-val" id="m_sent">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">۲. نصب و شمارنده SNAT</div>
                        <div class="m-val" id="m_snat" style="color:#facc15;">—</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">۳. دریافت واقعی در مقصد</div>
                        <div class="m-val" id="m_verified" style="color:#4ade80;">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">۴. نتیجه نهایی اسپوف</div>
                        <div class="m-val" id="m_class" style="font-size:11px;">NOT_TESTED</div>
                    </div>
                </div>

                <div class="terminal-window">
                    <div class="terminal-bar">
                        <span style="font-size: 11px; color: #64748b; font-family: monospace;">root@checkspoof:~# audit-log</span>
                        <button class="btn-sm" onclick="clearLogs()">پاکسازی لاگ</button>
                    </div>
                    <div id="terminal">System initialized. Waiting for pairing...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const ADMIN_KEY = "{{.AdminKey}}";
        let tokenVisible = false;

        function apiHeaders() {
            return {
                'Content-Type': 'application/json',
                'X-Admin-Key': ADMIN_KEY
            };
        }

        function toggleToken() {
            const el = document.getElementById('my_token');
            const btn = document.getElementById('toggle_btn');
            tokenVisible = !tokenVisible;
            el.innerText = tokenVisible ? el.getAttribute('data-token') : '••••••••••••••••••••••••••••••••••••••••••••••••••••';
            btn.innerText = tokenVisible ? 'مخفی کردن' : 'نمایش';
        }

        function copyToken() {
            const raw = document.getElementById('my_token').getAttribute('data-token');
            navigator.clipboard.writeText(raw);
            const btn = document.getElementById('copy_btn');
            btn.innerText = 'کپی شد ✓';
            setTimeout(() => { btn.innerText = 'کپی توکن'; }, 2000);
        }

        function savePublicIP() {
            const ip = document.getElementById('manual_public_ip').value.trim();
            fetch('/api/admin/public-ip', {
                method: 'POST',
                headers: apiHeaders(),
                body: JSON.stringify({ public_ip: ip })
            })
            .then(async r => {
                if (!r.ok) throw new Error(await r.text());
                return r.json();
            })
            .then(d => {
                document.getElementById('public_ip_badge').innerText = d.public_ip + " (" + d.public_ip_source + ")";
                const el = document.getElementById('my_token');
                el.setAttribute('data-token', d.pairing_token);
                if (tokenVisible) el.innerText = d.pairing_token;
                alert('آدرس IP عمومی و توکن جفت‌سازی به‌روزرسانی شد.');
            })
            .catch(err => alert('خطا: ' + err.message));
        }

        function setSpoof(ip) {
            document.getElementById('spoof_ip').value = ip;
            invalidatePrepare();
        }

        function invalidatePrepare() {
            document.getElementById('run_btn').disabled = true;
        }

        function clearLogs() {
            fetch('/api/admin/clear-logs', { method: 'POST', headers: apiHeaders() });
        }

        setInterval(() => {
            fetch('/api/admin/status', { headers: apiHeaders() })
            .then(r => r.json())
            .then(d => {
                document.getElementById('conn_state_badge').innerText = d.conn_state;
                document.getElementById('recv_state_badge').innerText = d.peer_receiver_state;
                document.getElementById('hb_badge').innerText = d.last_heartbeat;
                document.getElementById('local_ip_badge').innerText = d.local_outbound_ip;
                document.getElementById('public_ip_badge').innerText = d.public_ip + " (" + d.public_ip_source + ")";
                document.getElementById('local_recv_badge').innerText = "Local Receiver: " + d.local_receiver_state;

                if (d.peer_ip && d.peer_ip !== "—") {
                    document.getElementById('target_ip').value = d.peer_ip;
                }

                const prepBtn = document.getElementById('prep_btn');
                const runBtn = document.getElementById('run_btn');
                prepBtn.disabled = (d.conn_state !== "CONNECTED");
                runBtn.disabled = !(d.conn_state === "CONNECTED" && d.peer_receiver_state === "READY_TO_RECEIVE" && d.prepared_session_id);

                if (d.logs && d.logs.length > 0) {
                    const term = document.getElementById('terminal');
                    const joined = d.logs.join("\n");
                    if (term.innerText !== joined) {
                        term.innerText = joined;
                        term.scrollTop = term.scrollHeight;
                    }
                }
            }).catch(() => {});
        }, 1200);

        function pairServer() {
            const token = document.getElementById('remote_token').value.trim();
            const alertBox = document.getElementById('pair_alert');
            const btn = document.getElementById('pair_btn');
            if (!token) { alert('لطفاً توکن سرور دوم را وارد کنید'); return; }

            btn.disabled = true;
            alertBox.className = 'alert-box warning show';
            alertBox.innerHTML = '<strong>⏳ در حال احراز هویت متقابل TLS 1.3...</strong>';

            fetch('/api/admin/pair', {
                method: 'POST',
                headers: apiHeaders(),
                body: JSON.stringify({ remote_token: token })
            })
            .then(async r => {
                if (!r.ok) throw new Error(await r.text());
                return r.json();
            })
            .then(d => {
                document.getElementById('target_ip').value = d.peer_ip;
                document.getElementById('prep_btn').disabled = false;
                alertBox.className = 'alert-box success show';
                alertBox.innerHTML = '<strong>✅ اتصال امن TLS 1.3 برقرار شد!</strong>شناسه سرور مقابل: <code>' + d.peer_server_id + '</code> | آدرس مقصد: <code>' + d.peer_ip + '</code> (IP عمومی: <code>' + d.peer_public_ip + '</code>). اکنون دکمه «۱. آماده‌سازی شنونده گیرنده» را بزنید.';
            })
            .catch(err => {
                alertBox.className = 'alert-box failure show';
                alertBox.innerHTML = '<strong>❌ خطا در جفت‌سازی</strong>' + err.message;
            })
            .finally(() => {
                btn.disabled = false;
            });
        }

        function prepareReceiver() {
            const spoof = document.getElementById('spoof_ip').value.trim();
            const testType = document.getElementById('test_type').value;
            const count = parseInt(document.getElementById('packet_count').value, 10) || 3;
            const resBox = document.getElementById('test_result_box');
            const prepBtn = document.getElementById('prep_btn');

            prepBtn.disabled = true;
            resBox.className = 'alert-box warning show';
            resBox.innerHTML = '<strong>⏳ در حال راه‌اندازی سوکت شنونده روی سرور دوم...</strong>';

            fetch('/api/admin/prepare', {
                method: 'POST',
                headers: apiHeaders(),
                body: JSON.stringify({ spoof_ip: spoof, test_type: testType, packet_count: count })
            })
            .then(async r => {
                if (!r.ok) throw new Error(await r.text());
                return r.json();
            })
            .then(d => {
                document.getElementById('run_btn').disabled = false;
                resBox.className = 'alert-box success show';
                resBox.innerHTML = '<strong>🟢 گیرنده آماده دریافت پکت است (READY_TO_RECEIVE)</strong>سوکت <code>' + d.bound_address + '</code> برای نشست <code>' + d.session_id.substring(0, 8) + '</code> باز شد. اکنون دکمه «۲. شروع تست و ارزیابی» را بزنید.';
            })
            .catch(err => {
                resBox.className = 'alert-box failure show';
                resBox.innerHTML = '<strong>❌ خطا در آماده‌سازی گیرنده</strong>' + err.message;
            })
            .finally(() => {
                prepBtn.disabled = false;
            });
        }

        function runTest() {
            const runBtn = document.getElementById('run_btn');
            const resBox = document.getElementById('test_result_box');
            runBtn.disabled = true;
            resBox.className = 'alert-box warning show';
            resBox.innerHTML = '<strong>🚀 در حال اجرای تست ایزوله و اعتبارسنجی رمزنگاری پکت‌ها...</strong>';

            fetch('/api/admin/test', {
                method: 'POST',
                headers: apiHeaders(),
                body: JSON.stringify({})
            })
            .then(async r => {
                if (!r.ok) throw new Error(await r.text());
                return r.json();
            })
            .then(d => {
                document.getElementById('m_sent').innerText = (d.local_packet_gen_success ? "OK " : "FAIL ") + "(" + d.packets_sent + "/" + d.packets_attempted + ")";
                document.getElementById('m_snat').innerText = (d.snat_rule_installed ? "INSTALLED " : "FAIL ") + "(" + d.snat_packets_matched + " pkts)";
                document.getElementById('m_verified').innerText = d.remote_verified_count + (d.remote_spoof_verified ? " (SPOOFED)" : "");
                document.getElementById('m_class').innerText = d.primary_classification;

                resBox.className = 'alert-box show ' + (d.status_class || 'failure');
                resBox.innerHTML = '<strong>' + d.result_title + ' [' + d.primary_classification + ']</strong>' +
                    '<div style="margin-top:6px;"><b>مراحل ثبت‌شده:</b> <code>' + (d.classifications || []).join(' → ') + '</code></div>' +
                    '<div style="margin-top:4px;">' + d.confirmed_evidence + '</div>' +
                    '<div style="margin-top:4px; opacity:0.9;">' + d.possible_explanations + '</div>';
            })
            .catch(err => {
                resBox.className = 'alert-box show failure';
                resBox.innerHTML = '<strong>❌ خطا در اجرای تست</strong>' + err.message;
            });
        }
    </script>
</body>
</html>
`

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

func (s *AppServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if qKey := r.URL.Query().Get("key"); qKey != "" {
		if subtle.ConstantTimeCompare([]byte(qKey), []byte(s.AdminKey)) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     "cspf_admin_key",
				Value:    s.AdminKey,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
	}

	cookieKey := ""
	if c, err := r.Cookie("cspf_admin_key"); err == nil {
		cookieKey = c.Value
	}
	if subtle.ConstantTimeCompare([]byte(cookieKey), []byte(s.AdminKey)) != 1 &&
		subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("key")), []byte(s.AdminKey)) != 1 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="fa" dir="rtl"><body style="background:#070b14;color:#f8fafc;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;"><form method="GET" action="/" style="background:#0f172a;padding:28px;border-radius:12px;border:1px solid #1e293b;width:360px;"><h3 style="margin-top:0;color:#38bdf8;">🔒 ورود به داشبورد CheckSpoof</h3><p style="font-size:12px;color:#94a3b8;">کلید دسترسی مدیریت (چاپ‌شده در ترمینال سرور) را وارد کنید:</p><input name="key" type="password" placeholder="Admin Access Key" style="width:100%%;padding:10px;border-radius:8px;border:1px solid #334155;background:#090e1a;color:#fff;box-sizing:border-box;margin-bottom:12px;direction:ltr;"><button type="submit" style="width:100%%;padding:10px;background:#0284c7;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer;">ورود</button></form></body></html>`)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	_, _ = s.ResolveRoute(ctx, "8.8.8.8")
	cancel()

	s.mu.RLock()
	data := DashboardData{
		ServerID:        s.ServerID,
		LocalOutboundIP: s.LocalOutboundIP,
		PublicIP:        s.PublicIP,
		PublicIPSource:  s.PublicIPSource,
		BehindNAT:       s.BehindNAT,
		Port:            s.Port,
		Iface:           s.LocalInterface,
		CertFingerprint: s.CertFingerprint,
		AdminKey:        s.AdminKey,
	}
	s.mu.RUnlock()
	data.PairingToken = s.PairingToken()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = dashboardTmpl.Execute(w, data)
}

// Same-Port HTTP / TLS 1.3 Connection Multiplexer

type peekedConn struct {
	net.Conn
	peeked []byte
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if len(c.peeked) > 0 {
		n := copy(p, c.peeked)
		c.peeked = c.peeked[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func serveMultiplexed(rawLn net.Listener, tlsCert tls.Certificate, handler http.Handler) error {
	tlsCh := &chanListener{addr: rawLn.Addr(), ch: make(chan net.Conn, 64), done: make(chan struct{})}
	httpCh := &chanListener{addr: rawLn.Addr(), ch: make(chan net.Conn, 64), done: make(chan struct{})}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsLn := tls.NewListener(tlsCh, tlsCfg)

	srvTLS := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	srvHTTP := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() { _ = srvTLS.Serve(tlsLn) }()
	go func() { _ = srvHTTP.Serve(httpCh) }()

	for {
		conn, err := rawLn.Accept()
		if err != nil {
			close(tlsCh.done)
			close(httpCh.done)
			return err
		}
		go func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			first := make([]byte, 1)
			n, err := c.Read(first)
			_ = c.SetReadDeadline(time.Time{})
			if err != nil || n == 0 {
				_ = c.Close()
				return
			}
			pc := &peekedConn{Conn: c, peeked: first[:n]}
			if first[0] == 0x16 {
				select {
				case tlsCh.ch <- pc:
				case <-tlsCh.done:
					_ = pc.Close()
				}
			} else {
				select {
				case httpCh.ch <- pc:
				case <-httpCh.done:
					_ = pc.Close()
				}
			}
		}(conn)
	}
}

// IPv4 Classification & Validation Helpers

func isValidIPv4(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	return ip != nil && ip.To4() != nil
}

func IsPrivateOrReservedLocalIPv4(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}
	if ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() || ip4.IsMulticast() || ip4.IsUnspecified() {
		return true
	}
	if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	if ip4.Equal(net.IPv4bcast) {
		return true
	}
	return false
}

func IsPublicRoutableIPv4(ipStr string) bool {
	return isValidIPv4(ipStr) && !IsPrivateOrReservedLocalIPv4(ipStr)
}

func promptPortIfEmpty(cliPort string) string {
	if cliPort != "" {
		return strings.TrimSpace(cliPort)
	}
	if envPort := os.Getenv("PORT"); envPort != "" {
		return strings.TrimSpace(envPort)
	}
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		fmt.Print("🌐 Enter port for CheckSpoof [Press Enter for default 8085]: ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			if p, err := strconv.Atoi(input); err == nil && p > 0 && p < 65536 {
				return input
			}
		}
	}
	return "8085"
}

func bindAvailableListener(preferredPort string) (net.Listener, string) {
	basePort, err := strconv.Atoi(preferredPort)
	if err != nil || basePort <= 0 || basePort > 65535 {
		basePort = 8085
	}
	for i := 0; i < 20; i++ {
		tryPort := strconv.Itoa(basePort + i)
		ln, err := net.Listen("tcp", "0.0.0.0:"+tryPort)
		if err == nil {
			if i > 0 {
				fmt.Printf("⚠️ Port %d was busy! Automatically switched to free port %s.\n", basePort, tryPort)
			}
			return ln, tryPort
		}
	}
	fmt.Printf("[-] Error: Could not bind any free port starting from %d\n", basePort)
	os.Exit(1)
	return nil, ""
}

func (s *AppServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)

	mux.HandleFunc("/api/admin/public-ip", s.requireAdminAuth(s.handleAdminSetPublicIP))
	mux.HandleFunc("/api/admin/pair", s.requireAdminAuth(s.handleAdminPair))
	mux.HandleFunc("/api/admin/prepare", s.requireAdminAuth(s.handleAdminPrepare))
	mux.HandleFunc("/api/admin/test", s.requireAdminAuth(s.handleAdminTest))
	mux.HandleFunc("/api/admin/status", s.requireAdminAuth(s.handleAdminStatus))
	mux.HandleFunc("/api/admin/clear-logs", s.requireAdminAuth(s.handleAdminClearLogs))

	mux.HandleFunc("/api/peer/pair", s.requirePeerTLSAuth(s.handlePeerPair))
	mux.HandleFunc("/api/peer/heartbeat", s.requirePeerTLSAuth(s.handlePeerHeartbeat))
	mux.HandleFunc("/api/peer/prepare", s.requirePeerTLSAuth(s.handlePeerPrepare))
	mux.HandleFunc("/api/peer/results", s.requirePeerTLSAuth(s.handlePeerResults))

	return mux
}

func (s *AppServer) Shutdown() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.StopActiveReceiverSession()
	s.CleanupAllChains()
}

func main() {
	cliPort := flag.String("port", "", "Port to run CheckSpoof on (default 8085)")
	publicIPFlag := flag.String("public-ip", "", "Manually configured public IPv4 address of this server")
	integrationPeer := flag.String("integration-peer", "", "Run real two-server VPS integration test against this peer token and exit")
	spoofIPFlag := flag.String("spoof-ip", "8.8.8.8", "Spoofed source IPv4 address for -integration-peer mode")
	methodFlag := flag.String("method", "udp", "Test method for -integration-peer mode (udp or icmp)")
	countFlag := flag.Int("count", 3, "Packet count for -integration-peer mode (1..10)")
	flag.Parse()

	srv, err := NewAppServer(&RealCommandRunner{})
	if err != nil {
		fmt.Printf("[-] Initialization error: %v\n", err)
		os.Exit(1)
	}

	// Recover only chains orphaned by dead crashed PIDs; never touch active processes' chains.
	recCtx, recCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.RecoverOrphanedChainsFromJournal(recCtx)
	recCancel()

	if strings.TrimSpace(*publicIPFlag) != "" {
		if err := srv.SetManualPublicIP(*publicIPFlag); err != nil {
			fmt.Printf("[-] Invalid -public-ip value: %v\n", err)
			os.Exit(1)
		}
	} else if srv.PublicIP == IPValueUnknown {
		discCtx, discCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = srv.DiscoverAndSetPublicIP(discCtx)
		discCancel()
	}

	// Real Two-Server VPS CLI Integration Test Mode
	if strings.TrimSpace(*integrationPeer) != "" {
		srv.Port = "8085"
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		defer srv.CleanupAllChains()

		fmt.Println("======================================================================")
		fmt.Printf("🔬 Running Real Two-Server VPS Integration Test (%s)\n", strings.ToUpper(*methodFlag))
		fmt.Printf("📍 Local Outbound IP : %s (%s)\n", srv.LocalOutboundIP, srv.LocalInterface)
		fmt.Printf("🌐 Public IP         : %s (%s)\n", srv.PublicIP, srv.PublicIPSource)
		fmt.Printf("🎭 Spoof Source IP   : %s\n", *spoofIPFlag)
		fmt.Println("======================================================================")

		res, runErr := srv.RunRealVPSIntegrationTest(ctx, *integrationPeer, *spoofIPFlag, *methodFlag, *countFlag)
		if runErr != nil {
			fmt.Printf("[-] Integration test execution failed: %v\n", runErr)
			os.Exit(1)
		}

		fmt.Printf("1. Receiver Listener Ready : %v\n", res.ReceiverListenerReady)
		fmt.Printf("2. SNAT Rule Installed     : %v (Chain: %s, Outgoing Iface: %s, Outgoing Src: %s)\n", res.SNATRuleInstalled, res.IsolatedChainName, res.OutgoingInterface, res.OutgoingSourceIP)
		fmt.Printf("3. Local Packet Generation : %v (%d/%d packets sent)\n", res.LocalPacketGenSuccess, res.PacketsSent, res.PacketsAttempted)
		fmt.Printf("4. Local SNAT Rule Matched : %d packets (%d bytes)\n", res.SNATPacketsMatched, res.SNATBytesMatched)
		fmt.Printf("5. Remote Spoof Verified   : %v (%d verified packets with spoofed IP %s)\n", res.RemoteSpoofVerified, res.RemoteVerifiedCount, *spoofIPFlag)
		fmt.Printf("🏁 Final Classification    : %s\n", res.PrimaryClassification)
		fmt.Printf("📋 Evidence                : %s\n", res.ConfirmedEvidence)

		if res.PrimaryClassification == ClassSpoofSuccess && res.RemoteSpoofVerified {
			os.Exit(0)
		}
		os.Exit(2)
	}

	preferredPort := promptPortIfEmpty(*cliPort)
	listener, activePort := bindAvailableListener(preferredPort)
	srv.Port = activePort

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[+] Shutting down CheckSpoof and cleaning up owned firewall chains...")
		srv.Shutdown()
		_ = listener.Close()
		os.Exit(0)
	}()

	srv.StartHeartbeatLoop()
	srv.AddLog(fmt.Sprintf("Node %s initialized (LocalOutbound=%s on %s, PublicIP=%s [%s], BehindNAT=%v)",
		srv.ServerID, srv.LocalOutboundIP, srv.LocalInterface, srv.PublicIP, srv.PublicIPSource, srv.BehindNAT))

	ctrlIP := srv.EffectiveControlIP()
	fmt.Println("======================================================================")
	fmt.Printf("🛡️  CheckSpoof Enterprise v2 is running!\n")
	fmt.Printf("🆔 Server ID         : %s (Chain Prefix: CSPF_%s_*)\n", srv.ServerID, srv.InstanceChainID)
	fmt.Printf("📍 Local Outbound IP : %s (Interface: %s)\n", srv.LocalOutboundIP, srv.LocalInterface)
	fmt.Printf("🌐 Public IP         : %s (Source: %s, Behind NAT: %v)\n", srv.PublicIP, srv.PublicIPSource, srv.BehindNAT)
	fmt.Printf("🌐 Dashboard Login   : https://%s:%s/?key=%s\n", ctrlIP, srv.Port, srv.AdminKey)
	fmt.Printf("🌐 HTTP Fallback     : http://%s:%s/?key=%s\n", ctrlIP, srv.Port, srv.AdminKey)
	fmt.Printf("🔑 Admin Access Key  : %s\n", srv.AdminKey)
	fmt.Printf("🔗 Pairing Token     : %s\n", srv.PairingToken())
	fmt.Println("======================================================================")

	if err := serveMultiplexed(listener, srv.TLSCert, srv.Routes()); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Printf("[-] Server stopped: %v\n", err)
	}
}
