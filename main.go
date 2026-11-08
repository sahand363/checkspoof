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

// Test Result Classifications
const (
	ClassLocalGenSuccess     = "LOCAL_PACKET_GENERATION_SUCCESS"
	ClassLocalRuleMatched    = "LOCAL_FIREWALL_RULE_MATCHED"
	ClassRemoteVerified      = "REMOTE_PACKET_VERIFIED"
	ClassRemoteNotReceived   = "REMOTE_PACKET_NOT_RECEIVED"
	ClassReceiverUnavailable = "RECEIVER_UNAVAILABLE"
	ClassPermissionError     = "LOCAL_PERMISSION_ERROR"
	ClassRoutingError        = "ROUTING_ERROR"
	ClassTestIncomplete      = "TEST_INCOMPLETE"
)

// CommandRunner abstracts OS command execution for unit testing and security isolation.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, int, error)
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

// PacketListenerBinder abstracts UDP and Raw ICMP listener binding so startup cancellation
// and concurrent preparation can be deterministically tested without arbitrary sleeps.
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

// Cancel safely and idempotently cancels the receiver session.
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

// IsCancelled returns true if Cancel() has been invoked on this session.
func (rs *ReceiverSession) IsCancelled() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.cancelled
}

// GetState returns the current session state safely.
func (rs *ReceiverSession) GetState() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.State
}

// markDone closes DoneChan exactly once.
func (rs *ReceiverSession) markDone() {
	rs.doneOnce.Do(func() {
		close(rs.DoneChan)
	})
}

// PeerConfig holds authenticated peer details for persistent TLS connection monitoring.
type PeerConfig struct {
	Addr            string `json:"addr"`
	ServerID        string `json:"server_id"`
	PublicIP        string `json:"public_ip"`
	CertFingerprint string `json:"cert_fingerprint"`
	SharedSecret    string `json:"shared_secret"`
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

// AppServer encapsulates the entire state of a CheckSpoof node.
type AppServer struct {
	// prepMu serializes receiver session preparation transitions so concurrent callers
	// cleanly replace the prior session one at a time without holding s.mu while waiting.
	prepMu sync.Mutex

	mu              sync.RWMutex
	ServerID        string
	ServerIP        string
	Port            string
	PairingSecret   string
	AdminKey        string
	CertFingerprint string
	TLSCert         tls.Certificate
	Runner          CommandRunner
	Binder          PacketListenerBinder

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
	ActiveChains      map[string][]string

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
	pairSecret := randomHex(16)
	adminKey := randomHex(12)
	ip := getOutboundIP()

	cert, fp, err := generateSelfSignedCert(ip)
	if err != nil {
		return nil, err
	}

	s := &AppServer{
		ServerID:           srvID,
		ServerIP:           ip,
		PairingSecret:      pairSecret,
		AdminKey:           adminKey,
		CertFingerprint:    fp,
		TLSCert:            cert,
		Runner:             runner,
		Binder:             &RealListenerBinder{},
		ConnState:          ConnDisconnected,
		LocalReceiverState: RecvIdle,
		PeerReceiverState:  RecvIdle,
		SessionHistory:     make(map[string]*ReceiverSession),
		ActiveChains:       make(map[string][]string),
		stopCh:             make(chan struct{}),
	}
	return s, nil
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
	return fmt.Sprintf("%s:%s|%s|%s|%s", s.ServerIP, s.Port, s.ServerID, s.CertFingerprint, s.PairingSecret)
}

func ParsePairingToken(token string) (*PeerConfig, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, "|")
	if len(parts) != 4 {
		return nil, errors.New("فرمت توکن نامعتبر است؛ فرمت صحیح: IP:PORT|SERVER_ID|CERT_FP|SECRET")
	}
	addr, srvID, fp, secret := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3])
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || !isValidIPv4(host) {
		return nil, errors.New("آدرس IP یا پورت داخل توکن نامعتبر است")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return nil, errors.New("پورت داخل توکن نامعتبر است")
	}
	if len(srvID) < 8 || len(fp) != 64 || len(secret) < 16 {
		return nil, errors.New("فیلدهای امنیتی توکن ناقص یا نامعتبر هستند")
	}
	return &PeerConfig{
		Addr:            addr,
		ServerID:        srvID,
		PublicIP:        host,
		CertFingerprint: strings.ToLower(fp),
		SharedSecret:    secret,
	}, nil
}

// generateSelfSignedCert creates an in-memory ECDSA P-256 certificate and returns its SHA-256 fingerprint.
func generateSelfSignedCert(ipStr string) (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CheckSpoof Diagnostic Node"},
			CommonName:   ipStr,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if parsedIP := net.ParseIP(ipStr); parsedIP != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, parsedIP)
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

// buildPeerTLSClient builds an HTTPS client that pins the peer's SHA-256 certificate fingerprint.
func (s *AppServer) buildPeerTLSClient(expectedFP string, timeout time.Duration) *http.Client {
	expectedFP = strings.ToLower(strings.TrimSpace(expectedFP))
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{s.TLSCert},
		InsecureSkipVerify: true, // Verified explicitly in VerifyPeerCertificate below
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

// signPeerRequest computes HMAC-SHA256 over method, path, timestamp, and body using the shared secret.
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

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Peer-ID", s.ServerID)
	req.Header.Set("X-Peer-Cert-FP", s.CertFingerprint)
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

// BuildUDPPacketPayload creates a signed ASCII frame: CSPFv2|<SessionID>|udp|<Seq>|<TimestampMS>|<Nonce>|<HMAC>
func BuildUDPPacketPayload(secret, sessionID, nonce string, seq int, tsMillis int64) []byte {
	core := fmt.Sprintf("CSPFv2|%s|udp|%d|%d|%s", sessionID, seq, tsMillis, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(core))
	sig := hex.EncodeToString(mac.Sum(nil))
	return []byte(core + "|" + sig)
}

// ValidateUDPPacketPayload verifies a CSPFv2 UDP payload against the session parameters and secret.
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

// BuildICMPPatternHex builds a 16-byte (32 hex char) signed binary frame for `ping -p`:
// [0xC5 (1B)][SessionID prefix (4B)][Seq (1B)][Nonce prefix (4B)][HMAC-SHA256 truncated (6B)]
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

// ValidateICMPRawPacket validates a raw ICMP packet (Type 8, Code 0, ID, Seq, and 16-byte signed pattern).
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

// Isolated iptables SNAT Chain Management

type SNATChainIsolation struct {
	ChainName string
	JumpArgs  []string
	Runner    CommandRunner
	Server    *AppServer
	cleaned   bool
	mu        sync.Mutex
}

func (s *AppServer) SetupIsolatedSNATChain(ctx context.Context, shortID, iface, targetIP, spoofIP, proto string, udpPort int) (*SNATChainIsolation, error) {
	chainName := "CSPF_" + strings.ToUpper(shortID)
	if len(chainName) > 20 {
		chainName = chainName[:20]
	}

	_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", chainName)
	_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)

	if out, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-N", chainName); err != nil {
		return nil, fmt.Errorf("failed to create isolated iptables chain %s: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

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

	if out, _, err := s.Runner.Run(ctx, "iptables", ruleArgs...); err != nil {
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)
		return nil, fmt.Errorf("failed to insert SNAT rule into %s: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	verifyOut, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-L", chainName, "-v", "-n", "-x")
	if err != nil || !strings.Contains(string(verifyOut), "to:"+spoofIP) {
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", chainName)
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)
		return nil, fmt.Errorf("failed to verify SNAT rule in chain %s", chainName)
	}

	insertArgs := append([]string{"-t", "nat", "-I", "POSTROUTING", "1"}, jumpSpec...)
	if out, _, err := s.Runner.Run(ctx, "iptables", insertArgs...); err != nil {
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", chainName)
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)
		return nil, fmt.Errorf("failed to hook chain %s into POSTROUTING: %v (%s)", chainName, err, strings.TrimSpace(string(out)))
	}

	s.mu.Lock()
	s.ActiveChains[chainName] = jumpSpec
	s.mu.Unlock()

	return &SNATChainIsolation{
		ChainName: chainName,
		JumpArgs:  jumpSpec,
		Runner:    s.Runner,
		Server:    s,
	}, nil
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
	defer c.mu.Unlock()
	if c.cleaned {
		return
	}
	c.cleaned = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	delArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, c.JumpArgs...)
	_, _, _ = c.Runner.Run(ctx, "iptables", delArgs...)
	_, _, _ = c.Runner.Run(ctx, "iptables", "-t", "nat", "-F", c.ChainName)
	_, _, _ = c.Runner.Run(ctx, "iptables", "-t", "nat", "-X", c.ChainName)

	if c.Server != nil {
		c.Server.mu.Lock()
		delete(c.Server.ActiveChains, c.ChainName)
		c.Server.mu.Unlock()
	}
}

func (s *AppServer) CleanupAllChains() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.mu.Lock()
	chains := make(map[string][]string, len(s.ActiveChains))
	for k, v := range s.ActiveChains {
		chains[k] = v
	}
	s.ActiveChains = make(map[string][]string)
	s.mu.Unlock()

	for chainName, jumpSpec := range chains {
		delArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, jumpSpec...)
		_, _, _ = s.Runner.Run(ctx, "iptables", delArgs...)
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", chainName)
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", chainName)
	}

	out, _, err := s.Runner.Run(ctx, "iptables", "-t", "nat", "-S")
	if err != nil {
		return
	}
	var staleChains []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A POSTROUTING ") && strings.Contains(line, " -j CSPF_") {
			delLine := strings.Replace(line, "-A POSTROUTING ", "-D POSTROUTING ", 1)
			args := append([]string{"-t", "nat"}, strings.Fields(delLine)...)
			_, _, _ = s.Runner.Run(ctx, "iptables", args...)
		} else if strings.HasPrefix(line, "-N CSPF_") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				staleChains = append(staleChains, parts[1])
			}
		}
	}
	for _, ch := range staleChains {
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-F", ch)
		_, _, _ = s.Runner.Run(ctx, "iptables", "-t", "nat", "-X", ch)
	}
}

// Routing & Interface Discovery

func (s *AppServer) ResolveOutgoingInterface(ctx context.Context, targetIP string) (string, error) {
	if !isValidIPv4(targetIP) {
		return "", errors.New("invalid target IPv4 address")
	}
	out, exitCode, err := s.Runner.Run(ctx, "ip", "route", "get", targetIP)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("route lookup failed for %s: %v (%s)", targetIP, err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i, w := range fields {
		if w == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no outgoing interface found in route output: %s", strings.TrimSpace(string(out)))
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

// StartReceiverSession prepares a new receiver session using context.Background().
func (s *AppServer) StartReceiverSession(req PeerPrepareRequest, sharedSecret string) (*PeerPrepareResponse, error) {
	return s.StartReceiverSessionWithContext(context.Background(), req, sharedSecret)
}

// StartReceiverSessionWithContext safely detaches, cancels, and awaits any prior receiver session
// without holding s.mu, serializes concurrent preparation requests via s.prepMu, fences state
// updates via s.recvGen, and cleans up partial resources if cancelled during startup.
func (s *AppServer) StartReceiverSessionWithContext(callerCtx context.Context, req PeerPrepareRequest, sharedSecret string) (*PeerPrepareResponse, error) {
	if callerCtx == nil {
		callerCtx = context.Background()
	}

	// Validate request parameters before acquiring lifecycle locks
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

	// Serialize session preparation transitions so two concurrent callers cannot race
	// to bind the same port simultaneously.
	s.prepMu.Lock()
	defer s.prepMu.Unlock()

	// 1. Detach any previous session and register the new initializing session under s.mu.
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

	// Propagate callerCtx cancellation or server stop to sess.Cancel()
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

	// 2. If a prior session existed, cancel it and wait for its full cleanup WITHOUT holding s.mu!
	if oldSess != nil {
		oldSess.Cancel()
		<-oldSess.DoneChan
	}

	// 3. Check if this new session was cancelled while waiting for the old session to stop.
	if sess.IsCancelled() || sessCtx.Err() != nil || callerCtx.Err() != nil {
		s.abortStartupSession(sess, RecvIdle, "session cancelled before listener initialization")
		return nil, errors.New("receiver session cancelled before listener initialization")
	}

	binder := s.Binder
	if binder == nil {
		binder = &RealListenerBinder{}
	}

	// 4. Bind the requested socket (without holding s.mu).
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

		// Atomically verify the session was not cancelled while ListenUDP was running.
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

	// Raw ICMP Listener
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

// abortStartupSession cleans up a session that failed or was cancelled during startup.
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

// onSessionExit updates AppServer's LocalReceiverState only if sess is still the current generation.
func (s *AppServer) onSessionExit(sess *ReceiverSession, finalServerState string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recvGen == sess.Generation && s.ActiveRecvSession == sess {
		s.LocalReceiverState = finalServerState
	}
}

// StopActiveReceiverSession cancels the active receiver session (if any) and waits for cleanup.
func (s *AppServer) StopActiveReceiverSession() {
	s.mu.RLock()
	sess := s.ActiveRecvSession
	s.mu.RUnlock()
	if sess != nil {
		sess.Cancel()
		<-sess.DoneChan
	}
}

// CancelReceiverSession cancels a specific session ID (or the active session if sessionID == "")
// and waits for its cleanup to finish.
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

		s.AddLog(fmt.Sprintf("🎯 [Receiver] VERIFIED UDP Packet #%d from Spoofed IP %s (Session=%s)", seq, sourceIP, sess.SessionID[:8]))
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

		s.AddLog(fmt.Sprintf("🎯 [Receiver] VERIFIED ICMP Echo Request #%d (ID=%d, ICMPSeq=%d) from Spoofed IP %s", seq, icmpID, icmpSeq, sourceIP))
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

// Persistent Heartbeat & Connection State Machine

type HeartbeatPayload struct {
	ServerID        string `json:"server_id"`
	PublicIP        string `json:"public_ip"`
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
	var activeSessID string
	if s.ActiveRecvSession != nil {
		activeSessID = s.ActiveRecvSession.SessionID
	}
	s.mu.RUnlock()

	if peer == nil {
		return
	}

	reqPayload := HeartbeatPayload{
		ServerID:        s.ServerID,
		PublicIP:        s.ServerIP,
		ListenPort:      s.Port,
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
	SenderCertFingerprint string `json:"sender_cert_fingerprint"`
	SenderSecret          string `json:"sender_secret"`
}

type PeerPairResponse struct {
	ReceiverServerID        string `json:"receiver_server_id"`
	ReceiverPublicIP        string `json:"receiver_public_ip"`
	ReceiverCertFingerprint string `json:"receiver_cert_fingerprint"`
	ReceiverState           string `json:"receiver_state"`
}

func (s *AppServer) handlePeerPair(w http.ResponseWriter, r *http.Request) {
	var req PeerPairRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	if !isValidIPv4(req.SenderPublicIP) || len(req.SenderCertFingerprint) != 64 {
		http.Error(w, "Invalid peer identity parameters", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.Peer = &PeerConfig{
		Addr:            req.SenderAddr,
		ServerID:        req.SenderServerID,
		PublicIP:        req.SenderPublicIP,
		CertFingerprint: strings.ToLower(req.SenderCertFingerprint),
		SharedSecret:    s.PairingSecret,
	}
	s.ConnState = ConnConnected
	s.LastHeartbeat = time.Now()
	s.MissedHeartbeats = 0
	localRecv := s.LocalReceiverState
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("🔐 [Pairing] Authenticated mutual TLS pairing with peer %s (ID=%s)", req.SenderAddr, req.SenderServerID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PeerPairResponse{
		ReceiverServerID:        s.ServerID,
		ReceiverPublicIP:        s.ServerIP,
		ReceiverCertFingerprint: s.CertFingerprint,
		ReceiverState:           localRecv,
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
	}
	localRecv := s.LocalReceiverState
	var activeSessID string
	if s.ActiveRecvSession != nil {
		activeSessID = s.ActiveRecvSession.SessionID
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HeartbeatPayload{
		ServerID:        s.ServerID,
		PublicIP:        s.ServerIP,
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

	s.mu.Lock()
	s.ConnState = ConnAuthenticating
	s.PreparedSession = nil
	s.mu.Unlock()

	pairReq := PeerPairRequest{
		SenderServerID:        s.ServerID,
		SenderAddr:            fmt.Sprintf("%s:%s", s.ServerIP, s.Port),
		SenderPublicIP:        s.ServerIP,
		SenderCertFingerprint: s.CertFingerprint,
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

	s.mu.Lock()
	s.Peer = peerCfg
	s.ConnState = ConnConnected
	s.PeerReceiverState = pairResp.ReceiverState
	s.LastHeartbeat = time.Now()
	s.MissedHeartbeats = 0
	s.mu.Unlock()

	s.AddLog(fmt.Sprintf("✅ [Pairing] Connected over TLS 1.3 to Peer ID=%s (%s)", pairResp.ReceiverServerID, peerCfg.Addr))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "CONNECTED",
		"peer_server_id": pairResp.ReceiverServerID,
		"peer_ip":        peerCfg.PublicIP,
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

type AdminTestResult struct {
	SessionID             string                 `json:"session_id"`
	PrimaryClassification string                 `json:"primary_classification"`
	Classifications       []string               `json:"classifications"`
	PacketsAttempted      int                    `json:"packets_attempted"`
	PacketsSent           int                    `json:"packets_sent"`
	SNATPacketsMatched    int                    `json:"snat_packets_matched"`
	SNATBytesMatched      int                    `json:"snat_bytes_matched"`
	RemoteVerifiedCount   int                    `json:"remote_verified_count"`
	RemoteInvalidCount    int                    `json:"remote_invalid_count"`
	RemoteDuplicateCount  int                    `json:"remote_duplicate_count"`
	VerifiedPackets       []VerifiedPacketRecord `json:"verified_packets"`
	OutgoingInterface     string                 `json:"outgoing_interface"`
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

func (s *AppServer) executeCoordinatedTest(ctx context.Context, peer *PeerConfig, prep *PreparedSessionInfo) AdminTestResult {
	targetIP := peer.PublicIP
	res := AdminTestResult{
		SessionID:        prep.SessionID,
		PacketsAttempted: prep.PacketCount,
		Classifications:  []string{},
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

	iface, err := s.ResolveOutgoingInterface(ctx, targetIP)
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
	res.OutgoingInterface = iface

	shortID := prep.SessionID[:8]
	chainIso, err := s.SetupIsolatedSNATChain(ctx, shortID, iface, targetIP, prep.ExpectedSourceIP, prep.TestType, prep.UDPPort)
	if err != nil {
		s.AddLog(fmt.Sprintf("[-] [Firewall] %v", err))
		res.PrimaryClassification = ClassPermissionError
		res.Classifications = append(res.Classifications, ClassPermissionError)
		res.StatusClass = "failure"
		res.ResultTitle = "❌ خطای دسترسی یا فایروال محلی (LOCAL_PERMISSION_ERROR)"
		res.ConfirmedEvidence = fmt.Sprintf("ایجاد زنجیره ایزوله iptables شکست خورد: %v", err)
		res.PossibleExplanations = "برنامه بدون دسترسی root / CAP_NET_ADMIN اجرا شده یا ماژول nat کرنل فعال نیست."
		return res
	}
	defer chainIso.Cleanup()
	res.IsolatedChainName = chainIso.ChainName
	s.AddLog(fmt.Sprintf("[Sender] Created isolated SNAT chain %s on interface %s -> to:%s", chainIso.ChainName, iface, prep.ExpectedSourceIP))

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
		res.Classifications = append(res.Classifications, ClassLocalGenSuccess)
		s.AddLog(fmt.Sprintf("[Sender] Local packet generation: %d/%d packets transmitted.", packetsSent, prep.PacketCount))
	}

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

	res.RemoteVerifiedCount = remoteReport.VerifiedCount
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

	if remoteReport.VerifiedCount > 0 {
		res.PrimaryClassification = ClassRemoteVerified
		res.Classifications = append(res.Classifications, ClassRemoteVerified)
		res.StatusClass = "success"
		res.ResultTitle = "✅ تایید قطعی دریافت پکت اسپوف‌شده در مقصد (REMOTE_PACKET_VERIFIED)"
		res.ConfirmedEvidence = fmt.Sprintf("شواهد قطعی: %d پکت ارسال شد، %d پکت از زنجیره ایزوله %s عبور کرد و سرور دوم دقیقاً %d پکت با آدرس مبدا جعلی (%s) و امضای رمزنگاری معتبر دریافت کرد.", packetsSent, snatPkts, chainIso.ChainName, remoteReport.VerifiedCount, prep.ExpectedSourceIP)
		res.PossibleExplanations = "مسیر شبکه بین سرور اول و سرور دوم فاقد فیلترینگ خروجی مبدا (Egress Filtering / uRPF) برای این پروتکل و رنج آدرس است."
		return res
	}

	res.PrimaryClassification = ClassRemoteNotReceived
	res.Classifications = append(res.Classifications, ClassRemoteNotReceived)
	res.StatusClass = "failure"
	res.ResultTitle = "❌ عدم دریافت پکت در سرور دوم (REMOTE_PACKET_NOT_RECEIVED)"
	res.ConfirmedEvidence = fmt.Sprintf("شواهد ثبت‌شده: %d پکت در سرور اول تولید شد و %d پکت (%d بایت) در زنجیره ایزوله %s تغییر آدرس مبدا یافت، اما سرور دوم ۰ پکت معتبر دریافت کرد. (توجه: افزایش شمارنده SNAT صرفاً عبور از لایه netfilter کرنل را نشان می‌دهد و اثبات خروج فیزیکی یا عبور از روتر نیست.)", packetsSent, snatPkts, snatBytes, chainIso.ChainName)
	res.PossibleExplanations = "دلایل محتمل: ۱) اعمال فیلترینگ مبدا در روتر بالادست یا دیتاسنتر فرستنده (BCP 38 / uRPF)، ۲) دراپ شدن پکت در مسیر ترانزیت، ۳) مسدود بودن پورت یا پروتکل در فایروال ورودی سرور دوم، ۴) انتخاب نادرست کارت شبکه یا از دست رفتن پکت در شبکه."
	return res
}

func (s *AppServer) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	peerAddr := "—"
	peerID := "—"
	peerIP := "—"
	if s.Peer != nil {
		peerAddr = s.Peer.Addr
		peerID = s.Peer.ServerID
		peerIP = s.Peer.PublicIP
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
		"server_ip":            s.ServerIP,
		"port":                 s.Port,
		"conn_state":           s.ConnState,
		"local_receiver_state": s.LocalReceiverState,
		"peer_receiver_state":  s.PeerReceiverState,
		"peer_addr":            peerAddr,
		"peer_id":              peerID,
		"peer_ip":              peerIP,
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
	ServerIP        string
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
        .metric-box .m-val { font-size: 15px; font-weight: 800; font-family: monospace; color: #fff; }
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
                    <p>سامانه مهندسی تشخیص IP Spoofing با کنترل‌پلین TLS 1.3 و اعتبارسنجی رمزنگاری پکت‌ها</p>
                </div>
            </div>
            <div class="nav-pills">
                <div class="pill"><span>شناسه سرور:</span><strong>{{.ServerID}}</strong></div>
                <div class="pill"><span>آدرس:</span><strong>{{.ServerIP}}:{{.Port}}</strong></div>
                <div class="pill"><span>اینترفیس:</span><strong>{{.Iface}}</strong></div>
                <div class="pill"><span>وضعیت اتصال:</span><strong id="conn_state_badge">DISCONNECTED</strong></div>
                <div class="pill"><span>آمادگی گیرنده:</span><strong id="recv_state_badge">IDLE</strong></div>
                <div class="pill"><span>آخرین ضربان (Heartbeat):</span><strong id="hb_badge">—</strong></div>
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
                    <h2 class="card-title">⚙️ ۱. جفت‌سازی دوطرفه (TLS 1.3) و آماده‌سازی گیرنده</h2>
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
                    <h2 class="card-title">📊 ۲. شواهد تفکیک‌شده و مانیتورینگ زنده</h2>
                    <span id="local_recv_badge" style="font-size:11.5px; color:var(--text-muted); font-family:monospace;">Local Receiver: IDLE</span>
                </div>

                <div class="metrics-grid">
                    <div class="metric-box">
                        <div class="m-title">ارسال محلی (Sent)</div>
                        <div class="m-val" id="m_sent">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">شمارنده زنجیره SNAT</div>
                        <div class="m-val" id="m_snat" style="color:#facc15;">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">تایید رمزنگاری مقصد</div>
                        <div class="m-val" id="m_verified" style="color:#4ade80;">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">طبقه نهایی (Verdict)</div>
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
                alertBox.innerHTML = '<strong>✅ اتصال امن TLS 1.3 برقرار شد!</strong>شناسه سرور مقابل: <code>' + d.peer_server_id + '</code> | آدرس: <code>' + d.peer_ip + '</code>. اکنون دکمه «۱. آماده‌سازی شنونده گیرنده» را بزنید.';
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
                document.getElementById('m_sent').innerText = d.packets_sent + "/" + d.packets_attempted;
                document.getElementById('m_snat').innerText = d.snat_packets_matched + " pkts";
                document.getElementById('m_verified').innerText = d.remote_verified_count;
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
	iface, err := s.ResolveOutgoingInterface(ctx, "8.8.8.8")
	cancel()
	if err != nil {
		iface = "eth0"
	}

	data := DashboardData{
		ServerID:        s.ServerID,
		ServerIP:        s.ServerIP,
		Port:            s.Port,
		Iface:           iface,
		CertFingerprint: s.CertFingerprint,
		PairingToken:    s.PairingToken(),
		AdminKey:        s.AdminKey,
	}
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

// Helpers for IP Discovery and Port Binding

func getOutboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err == nil {
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		ip, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		if err == nil {
			trimmed := strings.TrimSpace(string(ip))
			if isValidIPv4(trimmed) {
				return trimmed
			}
		}
	}
	return "127.0.0.1"
}

func isValidIPv4(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	return ip != nil && ip.To4() != nil
}

func resolvePort() string {
	cliPort := flag.String("port", "", "Port to run CheckSpoof on (default 8085)")
	flag.Parse()

	if *cliPort != "" {
		return strings.TrimSpace(*cliPort)
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

// Shutdown cleanly stops background loops, active receiver sessions, and firewall rules.
func (s *AppServer) Shutdown() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.StopActiveReceiverSession()
	s.CleanupAllChains()
}

func main() {
	preferredPort := resolvePort()
	listener, activePort := bindAvailableListener(preferredPort)

	srv, err := NewAppServer(&RealCommandRunner{})
	if err != nil {
		fmt.Printf("[-] Initialization error: %v\n", err)
		os.Exit(1)
	}
	srv.Port = activePort

	srv.CleanupAllChains()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[+] Shutting down CheckSpoof and cleaning up temporary firewall chains...")
		srv.Shutdown()
		_ = listener.Close()
		os.Exit(0)
	}()

	srv.StartHeartbeatLoop()
	srv.AddLog(fmt.Sprintf("Node %s initialized on %s:%s (TLS Fingerprint=%s...)", srv.ServerID, srv.ServerIP, srv.Port, srv.CertFingerprint[:16]))

	fmt.Println("======================================================================")
	fmt.Printf("🛡️  CheckSpoof Enterprise v2 is running!\n")
	fmt.Printf("🆔 Server ID        : %s\n", srv.ServerID)
	fmt.Printf("🌐 Dashboard Login  : https://%s:%s/?key=%s\n", srv.ServerIP, srv.Port, srv.AdminKey)
	fmt.Printf("🌐 HTTP Fallback    : http://%s:%s/?key=%s\n", srv.ServerIP, srv.Port, srv.AdminKey)
	fmt.Printf("🔑 Admin Access Key : %s\n", srv.AdminKey)
	fmt.Printf("🔗 Pairing Token    : %s\n", srv.PairingToken())
	fmt.Println("======================================================================")

	if err := serveMultiplexed(listener, srv.TLSCert, srv.Routes()); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Printf("[-] Server stopped: %v\n", err)
	}
}
