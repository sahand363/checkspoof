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
	"path/filepath"
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
	ClassControlReceived          = "CONTROL_PACKET_RECEIVED"
	ClassControlPathBlocked       = "CONTROL_PATH_BLOCKED"
)

// DefaultUDPPort is the receiver UDP port used when none is configured.
const DefaultUDPPort = 5555

// Version is stamped at build time (-ldflags "-X main.Version=2.0.N").
var Version = "dev"

// validAdminKey accepts a persisted admin key: 16..128 chars of [A-Za-z0-9_-].
func validAdminKey(k string) bool {
	if len(k) < 16 || len(k) > 128 {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Packet frame markers: spoofed test frames vs. unspoofed control (baseline) frames.
const (
	frameMethodUDP     = "udp"
	frameMethodControl = "ctl"
	icmpMarkerSpoof    = 0xC5
	icmpMarkerControl  = 0xC6
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
	ControlSeen     map[int]bool
	ControlPackets  []VerifiedPacketRecord
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
	SessionID        string    `json:"session_id"`
	Nonce            string    `json:"nonce"`
	ExpectedSourceIP string    `json:"expected_source_ip"`
	TestType         string    `json:"test_type"`
	UDPPort          int       `json:"udp_port"`
	PacketCount      int       `json:"packet_count"`
	PreparedAt       time.Time `json:"prepared_at"`
}

// CrashJournalEntry records a process-owned SNAT chain on disk so a subsequent startup
// can clean up chains orphaned by a hard crash of a dead PID without touching live processes.
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

	// PanelTLS forces the browser panel onto HTTPS. Off by default: the panel
	// is served over plain HTTP (the server-to-server channel is always TLS 1.3).
	PanelTLS bool

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

func (s *AppServer) activeSharedSecret() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Peer != nil && s.Peer.SharedSecret != "" {
		return s.Peer.SharedSecret
	}
	return s.PairingSecret
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
	return buildUDPFrame(secret, sessionID, nonce, frameMethodUDP, seq, tsMillis)
}

// BuildUDPControlPayload builds an unspoofed baseline frame. It is sent from the sender's
// real address before the SNAT rule exists, to prove the path to the receiver port is open.
func BuildUDPControlPayload(secret, sessionID, nonce string, seq int, tsMillis int64) []byte {
	return buildUDPFrame(secret, sessionID, nonce, frameMethodControl, seq, tsMillis)
}

func buildUDPFrame(secret, sessionID, nonce, method string, seq int, tsMillis int64) []byte {
	core := fmt.Sprintf("CSPFv2|%s|%s|%d|%d|%s", sessionID, method, seq, tsMillis, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(core))
	sig := hex.EncodeToString(mac.Sum(nil))
	return []byte(core + "|" + sig)
}

func ValidateUDPPacketPayload(payload []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (int, error) {
	return validateUDPFrame(payload, secret, expectedSessionID, expectedNonce, frameMethodUDP, maxPackets)
}

// ValidateUDPControlPayload validates an unspoofed baseline frame.
func ValidateUDPControlPayload(payload []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (int, error) {
	return validateUDPFrame(payload, secret, expectedSessionID, expectedNonce, frameMethodControl, maxPackets)
}

func validateUDPFrame(payload []byte, secret, expectedSessionID, expectedNonce, method string, maxPackets int) (int, error) {
	parts := strings.Split(strings.TrimSpace(string(payload)), "|")
	if len(parts) != 7 {
		return 0, errors.New("invalid CSPFv2 frame format")
	}
	if parts[0] != "CSPFv2" || parts[2] != method {
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
	return buildICMPPattern(icmpMarkerSpoof, secret, sessionID, nonce, seq)
}

// BuildICMPControlPatternHex builds the ping pattern for an unspoofed baseline echo request.
func BuildICMPControlPatternHex(secret, sessionID, nonce string, seq int) (string, error) {
	return buildICMPPattern(icmpMarkerControl, secret, sessionID, nonce, seq)
}

func buildICMPPattern(marker byte, secret, sessionID, nonce string, seq int) (string, error) {
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
	frame[0] = marker
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
	return validateICMPRaw(icmpMarkerSpoof, rawPkt, secret, expectedSessionID, expectedNonce, maxPackets)
}

// ValidateICMPControlRawPacket validates an unspoofed baseline echo request.
func ValidateICMPControlRawPacket(rawPkt []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (seq int, icmpID uint16, icmpSeq uint16, err error) {
	return validateICMPRaw(icmpMarkerControl, rawPkt, secret, expectedSessionID, expectedNonce, maxPackets)
}

func validateICMPRaw(marker byte, rawPkt []byte, secret, expectedSessionID, expectedNonce string, maxPackets int) (seq int, icmpID uint16, icmpSeq uint16, err error) {
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
		if chunk[0] != marker {
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
	inst := sanitizeAlphaNumUpper(s.InstanceChainID, 6)
	for {
		seq := atomic.AddUint64(&s.chainSeq, 1)
		candidate := fmt.Sprintf("CSPF_%s_%08X", inst, seq&0xFFFFFFFF)
		if _, exists := s.OwnedChains[candidate]; !exists {
			return candidate
		}
	}
}

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

	s.chainsMu.Lock()
	s.OwnedChains[chainName] = iso
	s.chainsMu.Unlock()

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

	if out, _, err := s.Runner.Run(ctx, "iptables", ruleArgs...); err != nil {
		iso.Cleanup()
		return nil, fmt.Errorf("failed to insert SNAT rule into %s: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	iso.mu.Lock()
	iso.ruleAdded = true
	iso.mu.Unlock()
	s.syncCrashJournal()

	verifyOut, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-L", chainName, "-v", "-n", "-x")
	if err != nil || !strings.Contains(string(verifyOut), "to:"+spoofIP) {
		iso.Cleanup()
		return nil, fmt.Errorf("failed to verify SNAT rule in chain %s", chainName)
	}

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

	if jumpInserted && len(jumpArgs) > 0 {
		delArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, jumpArgs...)
		_, _, _ = c.Runner.Run(ctx, "iptables", delArgs...)
	}

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
		req.TimeoutSec = 45
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
		ControlSeen:      make(map[int]bool),
		ControlPackets:   []VerifiedPacketRecord{},
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

	var startupCompleted atomic.Bool
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-callerCtx.Done():
			if !startupCompleted.Load() {
				sess.Cancel()
			}
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
		startupCompleted.Store(true)
		sess.State = RecvReady
		sess.mu.Unlock()

		actualAddr := conn.LocalAddr().String()
		s.mu.Lock()
		if s.recvGen == sess.Generation {
			s.LocalReceiverState = RecvReady
		}
		s.mu.Unlock()

		s.AddLog(fmt.Sprintf("🟢 [Receiver] READY! Listening on UDP %s for spoofed IP %s (این سرور آماده دریافت پکت است)", actualAddr, req.ExpectedSourceIP))
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
	startupCompleted.Store(true)
	sess.State = RecvReady
	sess.mu.Unlock()

	s.mu.Lock()
	if s.recvGen == sess.Generation {
		s.LocalReceiverState = RecvReady
	}
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🟢 [Receiver] READY! Listening on ip4:icmp for spoofed IP %s (این سرور آماده دریافت پکت است)", req.ExpectedSourceIP))
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

// candidateSecrets returns the distinct shared secrets a valid frame may be signed with.
func (s *AppServer) candidateSecrets(primary string) []string {
	out := []string{primary}
	for _, alt := range []string{s.PairingSecret, s.activeSharedSecret()} {
		dup := false
		for _, have := range out {
			if have == alt {
				dup = true
				break
			}
		}
		if !dup && alt != "" {
			out = append(out, alt)
		}
	}
	return out
}

func (s *AppServer) validateUDPControlWithAnySecret(payload []byte, primarySecret string, sess *ReceiverSession) (int, error) {
	err := errors.New("no secret configured")
	for _, sec := range s.candidateSecrets(primarySecret) {
		var seq int
		if seq, err = ValidateUDPControlPayload(payload, sec, sess.SessionID, sess.Nonce, sess.MaxPackets); err == nil {
			return seq, nil
		}
	}
	return 0, err
}

func (s *AppServer) validateICMPControlWithAnySecret(rawPkt []byte, primarySecret string, sess *ReceiverSession) (int, uint16, uint16, error) {
	err := errors.New("no secret configured")
	for _, sec := range s.candidateSecrets(primarySecret) {
		var seq int
		var id, iSeq uint16
		if seq, id, iSeq, err = ValidateICMPControlRawPacket(rawPkt, sec, sess.SessionID, sess.Nonce, sess.MaxPackets); err == nil {
			return seq, id, iSeq, nil
		}
	}
	return 0, 0, 0, err
}

// recordControlPacket stores a verified baseline packet; returns false for duplicates.
func (sess *ReceiverSession) recordControlPacket(rec VerifiedPacketRecord) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.ControlSeen[rec.Seq] {
		return false
	}
	sess.ControlSeen[rec.Seq] = true
	sess.ControlPackets = append(sess.ControlPackets, rec)
	return true
}

func (s *AppServer) validateUDPWithAnySecret(payload []byte, primarySecret string, sess *ReceiverSession) (int, error) {
	seq, err := ValidateUDPPacketPayload(payload, primarySecret, sess.SessionID, sess.Nonce, sess.MaxPackets)
	if err == nil {
		return seq, nil
	}
	if primarySecret != s.PairingSecret {
		if seq2, err2 := ValidateUDPPacketPayload(payload, s.PairingSecret, sess.SessionID, sess.Nonce, sess.MaxPackets); err2 == nil {
			return seq2, nil
		}
	}
	altSecret := s.activeSharedSecret()
	if altSecret != primarySecret {
		if seq3, err3 := ValidateUDPPacketPayload(payload, altSecret, sess.SessionID, sess.Nonce, sess.MaxPackets); err3 == nil {
			return seq3, nil
		}
	}
	return 0, err
}

func (s *AppServer) validateICMPWithAnySecret(rawPkt []byte, primarySecret string, sess *ReceiverSession) (int, uint16, uint16, error) {
	seq, icmpID, icmpSeq, err := ValidateICMPRawPacket(rawPkt, primarySecret, sess.SessionID, sess.Nonce, sess.MaxPackets)
	if err == nil {
		return seq, icmpID, icmpSeq, nil
	}
	if primarySecret != s.PairingSecret {
		if seq2, id2, iSeq2, err2 := ValidateICMPRawPacket(rawPkt, s.PairingSecret, sess.SessionID, sess.Nonce, sess.MaxPackets); err2 == nil {
			return seq2, id2, iSeq2, nil
		}
	}
	altSecret := s.activeSharedSecret()
	if altSecret != primarySecret {
		if seq3, id3, iSeq3, err3 := ValidateICMPRawPacket(rawPkt, altSecret, sess.SessionID, sess.Nonce, sess.MaxPackets); err3 == nil {
			return seq3, id3, iSeq3, nil
		}
	}
	return 0, 0, 0, err
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
		if n <= 0 {
			continue
		}
		if cSeq, cErr := s.validateUDPControlWithAnySecret(buf[:n], secret, sess); cErr == nil {
			if sess.recordControlPacket(VerifiedPacketRecord{Seq: cSeq, SourceIP: sourceIP, Protocol: "udp-control", PayloadBytes: n, Timestamp: time.Now().Format("15:04:05.000")}) {
				s.AddLog(fmt.Sprintf("🧪 [Receiver] Control UDP packet #%d arrived from real sender IP %s (path is open)", cSeq, sourceIP))
			}
			continue
		}
		if sourceIP != sess.ExpectedSourceIP {
			continue
		}
		seq, valErr := s.validateUDPWithAnySecret(buf[:n], secret, sess)
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
		if n <= 0 {
			continue
		}
		if cSeq, cID, cISeq, cErr := s.validateICMPControlWithAnySecret(buf[:n], secret, sess); cErr == nil {
			if sess.recordControlPacket(VerifiedPacketRecord{Seq: cSeq, SourceIP: sourceIP, Protocol: "icmp-control", ICMPID: cID, ICMPSeq: cISeq, PayloadBytes: n, Timestamp: time.Now().Format("15:04:05.000")}) {
				s.AddLog(fmt.Sprintf("🧪 [Receiver] Control ICMP echo #%d arrived from real sender IP %s (path is open)", cSeq, sourceIP))
			}
			continue
		}
		if sourceIP != sess.ExpectedSourceIP {
			continue
		}
		seq, icmpID, icmpSeq, valErr := s.validateICMPWithAnySecret(buf[:n], secret, sess)
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

	// Do not allow an in-flight heartbeat response to clobber a freshly prepared session (< 3s old).
	if s.PreparedSession != nil && time.Since(s.PreparedSession.PreparedAt) < 3*time.Second && respPayload.ReceiverState == RecvIdle {
		// Keep s.PeerReceiverState = RecvReady
	} else {
		s.PeerReceiverState = respPayload.ReceiverState
		if s.PreparedSession != nil {
			if (respPayload.ActiveSessionID != "" && respPayload.ActiveSessionID != s.PreparedSession.SessionID) ||
				(respPayload.ReceiverState != RecvReady && respPayload.ReceiverState != RecvRunning) {
				s.PreparedSession = nil
			}
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
		if s.PreparedSession != nil && time.Since(s.PreparedSession.PreparedAt) < 3*time.Second && req.ReceiverState == RecvIdle {
			// Ignore stale in-flight heartbeat arriving right after session preparation
		} else {
			s.PeerReceiverState = req.ReceiverState
		}
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

	// Pass context.Background() so completion of the HTTP request never cancels the newly opened listener!
	resp, err := s.StartReceiverSessionWithContext(context.Background(), req, s.activeSharedSecret())
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
	ControlCount    int                    `json:"control_count"`
	ControlPackets  []VerifiedPacketRecord `json:"control_packets,omitempty"`
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
	ctlPkts := make([]VerifiedPacketRecord, len(sess.ControlPackets))
	copy(ctlPkts, sess.ControlPackets)
	resp := PeerSessionReportResponse{
		SessionID:       sess.SessionID,
		State:           sess.State,
		VerifiedCount:   len(sess.VerifiedPackets),
		InvalidCount:    sess.InvalidPackets,
		DuplicateCount:  sess.DuplicateCount,
		VerifiedPackets: pkts,
		LastError:       sess.LastError,
		ControlCount:    len(ctlPkts),
		ControlPackets:  ctlPkts,
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
		UDPPort     int    `json:"udp_port,omitempty"`
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
	if req.UDPPort == 0 {
		req.UDPPort = DefaultUDPPort
	}
	if req.UDPPort < 1 || req.UDPPort > 65535 {
		http.Error(w, "پورت UDP باید بین 1 تا 65535 باشد", http.StatusBadRequest)
		return
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
		UDPPort:          req.UDPPort,
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
		UDPPort:          req.UDPPort,
		PacketCount:      req.PacketCount,
		PreparedAt:       time.Now(),
	}
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🟢 [Sender] This server is ready to send packets! (سرور دوم روی %s در حال گوش دادن است — این سرور آماده ارسال پکت است)", prepResp.BoundAddress))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id":     sessionID,
		"receiver_state": prepResp.ReceiverState,
		"bound_address":  prepResp.BoundAddress,
		"udp_port":       req.UDPPort,
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
	ControlPacketsSent    int                    `json:"control_packets_sent"`
	ControlReceivedCount  int                    `json:"control_received_count"`
	ControlObservedIP     string                 `json:"control_observed_ip,omitempty"`
	UDPPort               int                    `json:"udp_port,omitempty"`
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
		http.Error(w, "گیرنده در وضعیت READY_TO_RECEIVE نیست. ابتدا دکمه «۱. سرور دوم گوش بدهد» را بزنید.", http.StatusPreconditionFailed)
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

// sendControlPackets sends unspoofed, HMAC-signed baseline packets from the sender's real
// address. For UDP the open socket is returned so the caller can hold its source port.
func (s *AppServer) sendControlPackets(ctx context.Context, peer *PeerConfig, prep *PreparedSessionInfo, targetIP string) (net.Conn, int) {
	sent := 0
	if prep.TestType == "udp" {
		raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, strconv.Itoa(prep.UDPPort)))
		if err != nil {
			s.AddLog(fmt.Sprintf("[-] [Control] %v", err))
			return nil, 0
		}
		conn, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			s.AddLog(fmt.Sprintf("[-] [Control] %v", err))
			return nil, 0
		}
		for seq := 1; seq <= prep.PacketCount; seq++ {
			payload := BuildUDPControlPayload(peer.SharedSecret, prep.SessionID, prep.Nonce, seq, time.Now().UnixMilli())
			if n, wErr := conn.Write(payload); wErr == nil && n == len(payload) {
				sent++
			}
			time.Sleep(100 * time.Millisecond)
		}
		s.AddLog(fmt.Sprintf("[Control] Sent %d unspoofed UDP baseline packets to %s:%d", sent, targetIP, prep.UDPPort))
		return conn, sent
	}

	for seq := 1; seq <= prep.PacketCount; seq++ {
		patHex, err := BuildICMPControlPatternHex(peer.SharedSecret, prep.SessionID, prep.Nonce, seq)
		if err != nil {
			break
		}
		pingCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		out, exitCode, _ := s.Runner.Run(pingCtx, "ping", "-c", "1", "-W", "1", "-s", "48", "-p", patHex, targetIP)
		cancel()
		if exitCode == 0 || strings.Contains(string(out), "transmitted") {
			sent++
		}
	}
	s.AddLog(fmt.Sprintf("[Control] Sent %d unspoofed ICMP baseline echo requests to %s", sent, targetIP))
	return nil, sent
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
	if prep.TestType == "udp" {
		res.UDPPort = prep.UDPPort
	}

	// Stage 1b: Unspoofed control (baseline) packets, sent BEFORE any SNAT rule exists.
	// If these never arrive, the receiver port/path is blocked and a missing spoofed
	// packet says nothing about source-address filtering.
	controlConn, controlSent := s.sendControlPackets(ctx, peer, prep, targetIP)
	if controlConn != nil {
		// Keep the control socket open until the spoofed packets are sent so the kernel cannot
		// reuse its source port (an existing conntrack entry would bypass the SNAT rule).
		defer controlConn.Close()
	}
	res.ControlPacketsSent = controlSent
	time.Sleep(300 * time.Millisecond)

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

	res.ControlReceivedCount = remoteReport.ControlCount
	if len(remoteReport.ControlPackets) > 0 {
		res.ControlObservedIP = remoteReport.ControlPackets[0].SourceIP
	}
	if res.ControlReceivedCount > 0 {
		res.Classifications = append(res.Classifications, ClassControlReceived)
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

	if res.ControlReceivedCount == 0 {
		res.RemoteSpoofVerified = false
		res.PrimaryClassification = ClassControlPathBlocked
		res.Classifications = append(res.Classifications, ClassControlPathBlocked)
		res.StatusClass = "warning"
		res.ResultTitle = "⚠️ نتیجه نامشخص — حتی پکت کنترلی بدون جعل هم به سرور دوم نرسید (CONTROL_PATH_BLOCKED)"
		portHint := ""
		if prep.TestType == "udp" {
			portHint = fmt.Sprintf(" پورت UDP %d را در فایروال سرور دوم و فایروال ابری (Security Group) باز کنید.", prep.UDPPort)
		}
		res.ConfirmedEvidence = fmt.Sprintf("%d پکت کنترلی با IP واقعی ارسال شد اما ۰ پکت به گیرنده رسید؛ بنابراین مسیر یا پورت مقصد بسته است و نبود پکت اسپوف‌شده دلیلی بر فیلترینگ BCP 38 نیست.", controlSent)
		res.PossibleExplanations = "فایروال سرور دوم، فایروال ابری یا فیلتر مسیر ترافیک تست را مسدود کرده است." + portHint
		return res
	}

	res.RemoteSpoofVerified = false
	res.PrimaryClassification = ClassRemoteNotReceived
	res.Classifications = append(res.Classifications, ClassRemoteNotReceived)
	res.StatusClass = "failure"
	res.ResultTitle = "❌ عدم دریافت پکت اسپوف‌شده در سرور دوم (REMOTE_PACKET_NOT_RECEIVED)"
	res.ConfirmedEvidence = fmt.Sprintf("شواهد تفکیک‌شده: ۱) شنونده مقصد آماده بود، ۲) زنجیره SNAT (%s) روی %s (آدرس محلی %s) نصب شد، ۳) %d پکت در مبدا تولید شد و ۴) %d پکت (%d بایت) با قانون SNAT محلی تطابق یافت؛ اما ۵) سرور دوم ۰ پکت با آدرس اسپوف‌شده (%s) دریافت کرد. (نصب قانون یا افزایش شمارنده SNAT به تنهایی دلیل موفقیت اسپوفینگ نیست.)",
		chainIso.ChainName, iface, routeInfo.SourceIP, packetsSent, snatPkts, snatBytes, prep.ExpectedSourceIP)
	res.ConfirmedEvidence += fmt.Sprintf(" پکت‌های کنترلی بدون جعل (%d/%d) از %s به گیرنده رسیدند، پس مسیر و پورت باز است.", res.ControlReceivedCount, controlSent, res.ControlObservedIP)
	res.PossibleExplanations = "مسیر باز است اما پکت‌های با مبدا جعلی حذف شدند؛ محتمل‌ترین دلیل فیلترینگ مبدا (BCP 38 / uRPF / anti-spoofing) در شبکه یا هایپروایزر فرستنده است."
	if res.ControlObservedIP != "" && res.ControlObservedIP != routeInfo.SourceIP {
		res.PossibleExplanations += fmt.Sprintf(" توجه: گیرنده IP فرستنده را %s دید در حالی که IP محلی %s است؛ فرستنده پشت NAT است و NAT بالادست آدرس مبدا را بازنویسی می‌کند.", res.ControlObservedIP, routeInfo.SourceIP)
	}
	return res
}

// RunRealVPSIntegrationTest executes a complete two-server spoofing verification test
// against a paired remote Linux VPS.
func (s *AppServer) RunRealVPSIntegrationTest(ctx context.Context, peerToken, spoofIP, testMethod string, packetCount, udpPort int) (AdminTestResult, error) {
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
	if udpPort == 0 {
		udpPort = DefaultUDPPort
	}
	if udpPort < 1 || udpPort > 65535 {
		return AdminTestResult{}, fmt.Errorf("invalid UDP port %d (use 1..65535)", udpPort)
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
		UDPPort:          udpPort,
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
		UDPPort:          udpPort,
		PacketCount:      packetCount,
		PreparedAt:       time.Now(),
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
	Version         string
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CheckSpoof</title>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
<style>
:root{
  --bg:#09090b; --surface:#111113; --surface-2:#18181b; --line:#232326; --line-2:#2e2e33;
  --text:#fafafa; --muted:#a1a1aa; --faint:#71717a;
  --accent:#a78bfa; --accent-ink:#0b0613;
  --ok:#34d399; --warn:#fbbf24; --bad:#f87171;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --r:14px;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text)}
body{font-family:'Vazirmatn',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 48px}
.mono,code,input.ltr{font-family:var(--mono);direction:ltr}
/* header */
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:28px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(140deg,#c4b5fd,#7c3aed);display:grid;place-items:center}
.logo svg{width:18px;height:18px}
.brand h1{margin:0;font-size:17px;font-weight:700;letter-spacing:-.01em}
.brand p{margin:0;color:var(--faint);font-size:12px}
.brand .ver{font-size:11px;font-weight:600;color:var(--accent,#a78bfa);background:rgba(167,139,250,.12);border-radius:6px;padding:2px 7px;margin-inline-start:6px;vertical-align:middle;direction:ltr;display:inline-block}
.status{display:flex;gap:8px;flex-wrap:wrap}
.tag{display:inline-flex;align-items:center;gap:7px;padding:6px 11px;border:1px solid var(--line);border-radius:999px;font-size:12px;color:var(--muted);background:var(--surface)}
.tag b{color:var(--text);font-weight:500;font-family:var(--mono);font-size:11.5px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--faint)}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(52,211,153,.15)}
.dot.warn{background:var(--warn)} .dot.bad{background:var(--bad)}
/* layout */
.grid{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:16px}
@media(max-width:900px){.grid{grid-template-columns:minmax(0,1fr)}}

.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:20px}
.card+.card{margin-top:16px}
.card h2{margin:0 0 4px;font-size:14px;font-weight:600}
.card .sub{margin:0 0 16px;color:var(--faint);font-size:12.5px}
.step{display:flex;gap:14px}
.step+.step{margin-top:20px;padding-top:20px;border-top:1px solid var(--line)}
.num{flex:none;width:24px;height:24px;border-radius:50%;border:1px solid var(--line-2);display:grid;place-items:center;font-size:12px;color:var(--muted);font-family:var(--mono)}
.step.done .num{background:var(--ok);border-color:var(--ok);color:#052e1f}
.step.active .num{border-color:var(--accent);color:var(--accent)}
.body{flex:1;min-width:0}
.body h3{margin:1px 0 10px;font-size:13.5px;font-weight:600}
/* form */
label{display:block;font-size:12px;color:var(--muted);margin:0 0 6px}
input,select{width:100%;height:40px;padding:0 12px;background:var(--surface-2);border:1px solid var(--line);border-radius:10px;color:var(--text);font:inherit;font-size:13px;outline:none;transition:border-color .15s,box-shadow .15s}
input.ltr{text-align:left;font-size:12.5px}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(167,139,250,.15)}
input[readonly]{color:var(--muted)}
.row{display:flex;gap:8px}
.row>input{flex:1}
.fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.fields .full{grid-column:1/-1}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.chip{border:1px solid var(--line);background:transparent;color:var(--muted);border-radius:999px;padding:3px 10px;font-family:var(--mono);font-size:11.5px;cursor:pointer}
.chip:hover{color:var(--text);border-color:var(--line-2)}
.hint{color:var(--faint);font-size:11.5px;margin-top:6px}
/* buttons */
.btn{height:40px;padding:0 16px;border-radius:10px;border:1px solid var(--line-2);background:var(--surface-2);color:var(--text);font:inherit;font-size:13px;font-weight:500;cursor:pointer;white-space:nowrap;transition:background .15s,opacity .15s,border-color .15s}
.btn:hover:not(:disabled){border-color:#3f3f46}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
.btn.primary:hover:not(:disabled){background:#b9a3fc}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn.ghost{height:30px;padding:0 10px;font-size:12px;background:transparent}
.actions{display:flex;gap:8px;margin-top:14px}
.actions .btn{flex:1}
/* token */
.token{display:flex;align-items:center;gap:8px;background:var(--surface-2);border:1px solid var(--line);border-radius:10px;padding:6px 6px 6px 12px;direction:ltr}
.token code{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--muted)}
/* notices */
.note{display:none;margin-top:12px;padding:10px 12px;border-radius:10px;font-size:12.5px;border:1px solid var(--line);background:var(--surface-2);color:var(--muted)}
.note.show{display:block}
.note.ok{border-color:rgba(52,211,153,.3);color:#a7f3d0}
.note.warn{border-color:rgba(251,191,36,.3);color:#fde68a}
.note.bad{border-color:rgba(248,113,113,.3);color:#fecaca}
/* result */
.verdict{display:flex;align-items:flex-start;gap:12px}
.verdict .badge{flex:none;width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:var(--surface-2);border:1px solid var(--line);font-size:16px}
.verdict.success .badge{background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.35);color:var(--ok)}
.verdict.warning .badge{background:rgba(251,191,36,.1);border-color:rgba(251,191,36,.35);color:var(--warn)}
.verdict.failure .badge{background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.35);color:var(--bad)}
.verdict h3{margin:0;font-size:14px;font-weight:600}
.verdict .cls{font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.stages{list-style:none;margin:18px 0 0;padding:0}
.stages li{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 0;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted)}
.stages li:first-child{border-top:0}
.stages .v{font-family:var(--mono);font-size:12px;color:var(--text);direction:ltr}
.stages .s{display:inline-flex;align-items:center;gap:8px}
.detail{margin-top:14px;font-size:12.5px;color:var(--muted)}
.detail p{margin:0 0 6px}
.empty{color:var(--faint);font-size:12.5px}
/* log */
.logbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
#terminal{height:300px;overflow:auto;margin:0;padding:12px;background:#060607;border:1px solid var(--line);border-radius:10px;font-family:var(--mono);font-size:11.5px;line-height:1.7;color:#d4d4d8;white-space:pre-wrap;direction:ltr;text-align:left}
#terminal::-webkit-scrollbar{width:8px}#terminal::-webkit-scrollbar-thumb{background:#27272a;border-radius:8px}
.listen{display:none;align-items:center;gap:8px;font-size:12px;color:#a7f3d0}
.listen.show{display:inline-flex}
.foot{margin-top:28px;color:var(--faint);font-size:11.5px;text-align:center}
@media(max-width:520px){.wrap{padding:20px 14px 36px}.actions{flex-direction:column}.actions .btn{flex:none;width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg></div>
      <div>
        <h1>CheckSpoof <span class="ver">v{{.Version}}</span></h1>
        <p>آزمون جعل آدرس مبدا بین دو سرور</p>
      </div>
    </div>
    <div class="status">
      <span class="tag"><span class="dot" id="conn_dot"></span><b id="conn_state_badge">DISCONNECTED</b></span>
      <span class="tag">محلی <b id="local_ip_badge">{{.LocalOutboundIP}}</b></span>
      <span class="tag">عمومی <b id="public_ip_badge">{{.PublicIP}}</b></span>
      <span class="tag">شناسه <b>{{.ServerID}}</b></span>
    </div>
  </header>

  <div class="grid">
    <div>
      <section class="card">
        <h2>توکن این سرور</h2>
        <p class="sub">این توکن را در داشبورد سرور فرستنده وارد کنید.</p>
        <div class="token">
          <code id="my_token" data-token="{{.PairingToken}}">{{.PairingToken}}</code>
          <button class="btn ghost" onclick="toggleToken()" id="toggle_btn">مخفی</button>
          <button class="btn ghost" onclick="copyToken()" id="copy_btn">کپی</button>
        </div>
        <details style="margin-top:12px">
          <summary style="cursor:pointer;color:var(--faint);font-size:12px">تنظیم دستی IP عمومی (برای سرورهای پشت NAT)</summary>
          <div class="row" style="margin-top:10px">
            <input type="text" id="manual_public_ip" class="ltr" placeholder="203.0.113.50">
            <button class="btn" onclick="savePublicIP()">ذخیره</button>
          </div>
          <div class="note" id="pubip_note"></div>
        </details>
      </section>

      <section class="card">
        <div class="step active" id="step1">
          <div class="num">1</div>
          <div class="body">
            <h3>اتصال به سرور گیرنده</h3>
            <div class="row">
              <input type="text" id="remote_token" class="ltr" placeholder="IP:PORT|SERVER_ID|CERT_FP|SECRET">
              <button class="btn primary" onclick="pairServer()" id="pair_btn">اتصال</button>
            </div>
            <div class="note" id="pair_alert"></div>
          </div>
        </div>

        <div class="step" id="step2">
          <div class="num">2</div>
          <div class="body">
            <h3>تنظیمات آزمون</h3>
            <div class="fields">
              <div>
                <label for="test_type">پروتکل</label>
                <select id="test_type" onchange="onTypeChange()">
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
              </div>
              <div>
                <label for="packet_count">تعداد پکت</label>
                <input type="number" id="packet_count" class="ltr" value="3" min="1" max="10" onchange="invalidatePrepare()">
              </div>
              <div>
                <label for="spoof_ip">IP جعلی مبدا</label>
                <input type="text" id="spoof_ip" class="ltr" value="8.8.8.8" oninput="invalidatePrepare()">
              </div>
              <div id="udp_port_wrap">
                <label for="udp_port">پورت UDP گیرنده</label>
                <input type="number" id="udp_port" class="ltr" value="5555" min="1" max="65535" onchange="invalidatePrepare()">
              </div>
              <div class="full">
                <label for="target_ip">مقصد</label>
                <input type="text" id="target_ip" class="ltr" readonly placeholder="—">
                <div class="chips">
                  <button class="chip" onclick="setSpoof('8.8.8.8')">8.8.8.8</button>
                  <button class="chip" onclick="setSpoof('1.1.1.1')">1.1.1.1</button>
                  <button class="chip" onclick="setSpoof('9.9.9.9')">9.9.9.9</button>
                </div>
                <div class="hint" id="port_hint">پورت UDP باید در فایروال سرور گیرنده باز باشد.</div>
              </div>
            </div>
          </div>
        </div>

        <div class="step" id="step3">
          <div class="num">3</div>
          <div class="body">
            <h3>اجرا</h3>
            <div class="actions">
              <button id="prep_btn" class="btn" disabled onclick="prepareReceiver()">آماده‌سازی گیرنده</button>
              <button id="run_btn" class="btn primary" disabled onclick="runTest()">ارسال پکت‌ها</button>
            </div>
            <div class="note" id="prep_note"></div>
          </div>
        </div>
      </section>
    </div>

    <div>
      <section class="card">
        <h2>نتیجه</h2>
        <p class="sub">ابتدا پکت کنترلی بدون جعل، سپس پکت‌های جعلی ارسال می‌شوند.</p>
        <div id="result"><p class="empty">هنوز آزمونی اجرا نشده است.</p></div>
      </section>

      <section class="card">
        <div class="logbar">
          <h2 style="margin:0">گزارش زنده</h2>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="listen" id="listen_badge"><span class="dot ok"></span>این سرور در حال گوش دادن است</span>
            <button class="btn ghost" onclick="clearLogs()">پاک کردن</button>
          </div>
        </div>
        <pre id="terminal">Waiting for pairing…</pre>
      </section>
    </div>
  </div>
  <p class="foot">Peer ID <span class="mono" id="peer_id">—</span> · Heartbeat <span class="mono" id="hb_badge">—</span> · Peer receiver <span class="mono" id="recv_state_badge">IDLE</span></p>
</div>

<script>
const ADMIN_KEY = "{{.AdminKey}}";
let tokenVisible = true;
const $ = id => document.getElementById(id);

function headers(){ return {'Content-Type':'application/json','X-Admin-Key':ADMIN_KEY}; }
function api(path, body){
  return fetch(path,{method:'POST',headers:headers(),body:JSON.stringify(body||{})})
    .then(async r => { if(!r.ok) throw new Error((await r.text()).trim()); const t = await r.text(); return t ? JSON.parse(t) : {}; });
}
function note(id, kind, text){ const el=$(id); el.className='note show '+(kind||''); el.textContent=text; }
function hideNote(id){ $(id).className='note'; }

function toggleToken(){
  const el=$('my_token'); tokenVisible=!tokenVisible;
  el.textContent = tokenVisible ? el.getAttribute('data-token') : '••••••••••••••••••••••••••••••••';
  $('toggle_btn').textContent = tokenVisible ? 'مخفی' : 'نمایش';
}
function copyFallback(text){
  const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.top='-9999px';
  document.body.appendChild(ta); ta.select(); let ok=false; try{ok=document.execCommand('copy');}catch(e){}
  document.body.removeChild(ta); return ok;
}
function copyToken(){
  const raw=$('my_token').getAttribute('data-token'), btn=$('copy_btn');
  const done=()=>{ btn.textContent='کپی شد'; setTimeout(()=>btn.textContent='کپی',1600); };
  const fb=()=>{ if(copyFallback(raw)) done(); else window.prompt('Copy token:', raw); };
  if(navigator.clipboard && window.isSecureContext){ navigator.clipboard.writeText(raw).then(done).catch(fb); } else { fb(); }
}
function savePublicIP(){
  api('/api/admin/public-ip',{public_ip:$('manual_public_ip').value.trim()})
    .then(d=>{ $('public_ip_badge').textContent=d.public_ip; const el=$('my_token'); el.setAttribute('data-token',d.pairing_token); if(tokenVisible) el.textContent=d.pairing_token; note('pubip_note','ok','IP عمومی و توکن به‌روزرسانی شد.'); })
    .catch(e=>note('pubip_note','bad',e.message));
}
function setSpoof(ip){ $('spoof_ip').value=ip; invalidatePrepare(); }
function onTypeChange(){
  const udp=$('test_type').value==='udp';
  $('udp_port_wrap').style.display = udp ? '' : 'none';
  $('port_hint').textContent = udp ? 'پورت UDP باید در فایروال سرور گیرنده باز باشد.' : 'ICMP روی سوکت خام دریافت می‌شود و پورت لازم ندارد.';
  invalidatePrepare();
}
function invalidatePrepare(){ $('run_btn').disabled=true; }
function clearLogs(){ api('/api/admin/clear-logs').catch(()=>{}); }

function setStep(n){
  [1,2,3].forEach(i=>{ const s=$('step'+i); s.classList.toggle('done', i<n); s.classList.toggle('active', i===n); });
}

function poll(){
  fetch('/api/admin/status',{headers:headers()}).then(r=>r.json()).then(d=>{
    const connected = d.conn_state==='CONNECTED';
    $('conn_state_badge').textContent=d.conn_state;
    $('conn_dot').className='dot '+(connected?'ok':(d.conn_state==='ERROR'?'bad':''));
    $('recv_state_badge').textContent=d.peer_receiver_state||'—';
    $('hb_badge').textContent=d.last_heartbeat;
    $('peer_id').textContent=d.peer_id;
    $('local_ip_badge').textContent=d.local_outbound_ip;
    $('public_ip_badge').textContent=d.public_ip;
    $('listen_badge').classList.toggle('show', d.local_receiver_state==='READY_TO_RECEIVE'||d.local_receiver_state==='TEST_RUNNING');
    if(d.peer_ip && d.peer_ip!=='—') $('target_ip').value=d.peer_ip;
    $('prep_btn').disabled=!connected;
    const ready = connected && d.peer_receiver_state==='READY_TO_RECEIVE' && d.prepared_session_id;
    $('run_btn').disabled=!ready;
    setStep(!connected ? 1 : (ready ? 3 : 2));
    if(d.logs && d.logs.length){
      const term=$('terminal'), joined=d.logs.join('\n');
      if(term.textContent!==joined){ const atEnd = term.scrollHeight-term.scrollTop-term.clientHeight<40; term.textContent=joined; if(atEnd) term.scrollTop=term.scrollHeight; }
    }
  }).catch(()=>{});
}
setInterval(poll,1200); poll();

function pairServer(){
  const token=$('remote_token').value.trim();
  if(!token){ note('pair_alert','warn','توکن سرور گیرنده را وارد کنید.'); return; }
  const btn=$('pair_btn'); btn.disabled=true; note('pair_alert','','در حال اتصال امن…');
  api('/api/admin/pair',{remote_token:token})
    .then(d=>{ $('target_ip').value=d.peer_ip; $('prep_btn').disabled=false; note('pair_alert','ok','متصل شد به '+d.peer_ip); })
    .catch(e=>note('pair_alert','bad',e.message))
    .finally(()=>btn.disabled=false);
}

function prepareReceiver(){
  const body={
    spoof_ip:$('spoof_ip').value.trim(),
    test_type:$('test_type').value,
    packet_count:parseInt($('packet_count').value,10)||3
  };
  if(body.test_type==='udp') body.udp_port=parseInt($('udp_port').value,10)||5555;
  const btn=$('prep_btn'); btn.disabled=true; note('prep_note','','در حال آماده‌سازی گیرنده…');
  api('/api/admin/prepare',body)
    .then(d=>{ $('run_btn').disabled=false; note('prep_note','ok','گیرنده آماده است'+(d.udp_port && body.test_type==='udp' ? ' (UDP '+d.udp_port+')' : '')+'. حالا پکت‌ها را ارسال کنید.'); })
    .catch(e=>note('prep_note','bad',e.message))
    .finally(()=>btn.disabled=false);
}

function el(tag, cls, text){ const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e; }
function stageRow(label, ok, value){
  const li=el('li'); const s=el('span','s'); s.appendChild(el('span','dot '+(ok===true?'ok':ok===false?'bad':'')));
  s.appendChild(el('span','',label)); li.appendChild(s); li.appendChild(el('span','v',value)); return li;
}
function renderResult(d){
  const box=$('result'); box.innerHTML='';
  const kind=d.status_class||'failure';
  const v=el('div','verdict '+kind);
  v.appendChild(el('div','badge', kind==='success'?'✓':(kind==='warning'?'!':'×')));
  const t=el('div'); t.appendChild(el('h3','',String(d.result_title||'').replace(/^[^\p{L}\p{N}]+/u,''))); t.appendChild(el('div','cls',d.primary_classification)); v.appendChild(t);
  box.appendChild(v);
  const ul=el('ul','stages');
  const ctlOk = d.control_packets_sent ? d.control_received_count>0 : null;
  ul.appendChild(stageRow('مسیر کنترلی (بدون جعل)', ctlOk, (d.control_received_count||0)+'/'+(d.control_packets_sent||0)+(d.control_observed_ip?'  '+d.control_observed_ip:'')));
  ul.appendChild(stageRow('قانون SNAT', d.snat_rule_installed, d.isolated_chain_name||'—'));
  ul.appendChild(stageRow('ارسال محلی', d.local_packet_gen_success, d.packets_sent+'/'+d.packets_attempted));
  ul.appendChild(stageRow('تطابق در کرنل', d.snat_packets_matched>0, d.snat_packets_matched+' pkts'));
  ul.appendChild(stageRow('دریافت با IP جعلی', d.remote_spoof_verified, String(d.remote_verified_count)));
  box.appendChild(ul);
  const det=el('div','detail'); det.appendChild(el('p','',d.confirmed_evidence)); det.appendChild(el('p','',d.possible_explanations)); box.appendChild(det);
}
function runTest(){
  const btn=$('run_btn'); btn.disabled=true;
  $('result').innerHTML=''; $('result').appendChild(el('p','empty','در حال ارسال پکت کنترلی و پکت‌های جعلی…'));
  api('/api/admin/test',{}).then(renderResult).catch(e=>{ $('result').innerHTML=''; renderResult({status_class:'failure',result_title:'خطا در اجرای آزمون',primary_classification:'ERROR',confirmed_evidence:e.message,possible_explanations:'',packets_sent:0,packets_attempted:0,snat_packets_matched:0,remote_verified_count:0}); });
}
onTypeChange();
</script>
</body>
</html>
`

const loginHTML = `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CheckSpoof</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net"><link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet">
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0b0f;color:#ededf0;font-family:Vazirmatn,system-ui,sans-serif;padding:20px}
form{width:100%;max-width:360px;background:#131318;border:1px solid #23232b;border-radius:16px;padding:28px}
h3{margin:0 0 6px;font-size:18px}p{margin:0 0 18px;color:#8b8b96;font-size:13px;line-height:1.7}
input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2a2a33;background:#0b0b0f;color:#fff;font-size:14px;direction:ltr;outline:none;margin-bottom:12px}
input:focus{border-color:#a78bfa}button{width:100%;padding:12px;border:0;border-radius:10px;background:#a78bfa;color:#0b0b0f;font-weight:700;font-size:14px;font-family:inherit;cursor:pointer}
code{direction:ltr;display:inline-block;background:#1c1c23;padding:1px 6px;border-radius:5px;color:#c4b5fd}</style></head>
<body><form method="GET" action="/"><h3>ورود به CheckSpoof</h3><p>کلید مدیریت را وارد کنید. آن را در منوی SSH با دستور <code>sudo spoof</code> می‌بینید.</p>
<input name="key" type="password" placeholder="Admin Access Key" autocomplete="current-password" autofocus><button type="submit">ورود</button></form></body></html>`

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

func (s *AppServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if qKey := r.URL.Query().Get("key"); qKey != "" {
		if subtle.ConstantTimeCompare([]byte(qKey), []byte(s.AdminKey)) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     "cspf_admin_key",
				Value:    s.AdminKey,
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
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
		_, _ = io.WriteString(w, loginHTML)
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
		Version:         Version,
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

// writeRuntimePort records the port actually bound (it may differ from the
// requested one when that was busy) so the SSH menu can show the right link.
// systemd sets RUNTIME_DIRECTORY when the unit declares RuntimeDirectory=.
func writeRuntimePort(port string) {
	dir := strings.TrimSpace(os.Getenv("RUNTIME_DIRECTORY"))
	if dir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "port"), []byte(port+"\n"), 0o644)
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

	return s.panelSchemeGuard(mux)
}

// panelSchemeGuard sends plain-HTTP browser requests to HTTPS when panel SSL
// is on. Peer endpoints already reject non-TLS requests on their own.
func (s *AppServer) panelSchemeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.PanelTLS && r.TLS == nil && !strings.HasPrefix(r.URL.Path, "/api/peer/") {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PanelScheme is the scheme the panel link should use.
func (s *AppServer) PanelScheme() string {
	if s.PanelTLS {
		return "https"
	}
	return "http"
}

func parseBoolEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
	udpPortFlag := flag.Int("udp-port", DefaultUDPPort, "Receiver UDP port for -integration-peer mode (must be open on Server B)")
	adminKeyFlag := flag.String("admin-key", "", "Fixed admin access key (16+ chars of A-Z a-z 0-9 - _); also read from CHECKSPOOF_ADMIN_KEY")
	versionFlag := flag.Bool("version", false, "Print the version and exit")
	panelTLSFlag := flag.Bool("panel-tls", false, "Serve the browser panel over HTTPS only (self-signed); also CHECKSPOOF_PANEL_TLS=1")
	flag.Parse()

	if *versionFlag || (flag.NArg() > 0 && flag.Arg(0) == "version") {
		fmt.Println(Version)
		return
	}

	srv, err := NewAppServer(&RealCommandRunner{})
	if err != nil {
		fmt.Printf("[-] Initialization error: %v\n", err)
		os.Exit(1)
	}

	fixedKey := strings.TrimSpace(*adminKeyFlag)
	if fixedKey == "" {
		fixedKey = strings.TrimSpace(os.Getenv("CHECKSPOOF_ADMIN_KEY"))
	}
	if fixedKey != "" {
		if !validAdminKey(fixedKey) {
			fmt.Println("[-] Invalid admin key: use 16..128 characters of A-Z a-z 0-9 - _")
			os.Exit(1)
		}
		srv.AdminKey = fixedKey
	}
	srv.PanelTLS = *panelTLSFlag || parseBoolEnv(os.Getenv("CHECKSPOOF_PANEL_TLS"))

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

		res, runErr := srv.RunRealVPSIntegrationTest(ctx, *integrationPeer, *spoofIPFlag, *methodFlag, *countFlag, *udpPortFlag)
		if runErr != nil {
			fmt.Printf("[-] Integration test execution failed: %v\n", runErr)
			os.Exit(1)
		}

		fmt.Printf("1. Receiver Listener Ready : %v\n", res.ReceiverListenerReady)
		fmt.Printf("2. SNAT Rule Installed     : %v (Chain: %s, Outgoing Iface: %s, Outgoing Src: %s)\n", res.SNATRuleInstalled, res.IsolatedChainName, res.OutgoingInterface, res.OutgoingSourceIP)
		fmt.Printf("3. Local Packet Generation : %v (%d/%d packets sent)\n", res.LocalPacketGenSuccess, res.PacketsSent, res.PacketsAttempted)
		fmt.Printf("0. Control Path Check      : %d/%d unspoofed packets arrived (seen as %s)\n", res.ControlReceivedCount, res.ControlPacketsSent, res.ControlObservedIP)
		fmt.Printf("4. Local SNAT Rule Matched : %d packets (%d bytes)\n", res.SNATPacketsMatched, res.SNATBytesMatched)
		fmt.Printf("5. Remote Spoof Verified   : %v (%d verified packets with spoofed IP %s)\n", res.RemoteSpoofVerified, res.RemoteVerifiedCount, *spoofIPFlag)
		fmt.Printf("🏁 Final Classification    : %s\n", res.PrimaryClassification)
		fmt.Printf("📋 Evidence                : %s\n", res.ConfirmedEvidence)

		if res.PrimaryClassification == ClassSpoofSuccess && res.RemoteSpoofVerified {
			os.Exit(0)
		}
		if res.PrimaryClassification == ClassControlPathBlocked {
			os.Exit(3)
		}
		os.Exit(2)
	}

	preferredPort := promptPortIfEmpty(*cliPort)
	listener, activePort := bindAvailableListener(preferredPort)
	srv.Port = activePort
	writeRuntimePort(activePort)

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
	fmt.Printf("🛡️  CheckSpoof v%s is running!\n", Version)
	fmt.Printf("🆔 Server ID         : %s (Chain Prefix: CSPF_%s_*)\n", srv.ServerID, srv.InstanceChainID)
	fmt.Printf("📍 Local Outbound IP : %s (Interface: %s)\n", srv.LocalOutboundIP, srv.LocalInterface)
	fmt.Printf("🌐 Public IP         : %s (Source: %s, Behind NAT: %v)\n", srv.PublicIP, srv.PublicIPSource, srv.BehindNAT)
	fmt.Printf("🌐 Dashboard Login   : %s://%s:%s/?key=%s\n", srv.PanelScheme(), ctrlIP, srv.Port, srv.AdminKey)
	if srv.PanelTLS {
		fmt.Println("🔒 Panel SSL         : on (self-signed; plain HTTP redirects to HTTPS)")
	} else {
		fmt.Println("🔓 Panel SSL         : off (plain HTTP; turn on with -panel-tls)")
	}
	fmt.Printf("🔑 Admin Access Key  : %s\n", srv.AdminKey)
	fmt.Printf("🔗 Pairing Token     : %s\n", srv.PairingToken())
	fmt.Println("======================================================================")

	if err := serveMultiplexed(listener, srv.TLSCert, srv.Routes()); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Printf("[-] Server stopped: %v\n", err)
	}
}
