package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type MockCommandCall struct {
	Name string
	Args []string
}

// MockCommandRunner simulates `ip route` and a stateful kernel `iptables -t nat` table
// so multi-session, multi-process, and partial-initialization tests can verify exact NAT table state.
type MockCommandRunner struct {
	mu               sync.Mutex
	Calls            []MockCommandCall
	LastSpoofIP      string
	RouteFail        bool
	PermFail         bool
	FailOnAppend     bool
	FailOnPostInsert bool
	RouteTable       map[string]string
	ChainSpoofIPs    map[string]string
	NatChains        map[string][]string
	PostroutingRules []string
}

func (m *MockCommandRunner) IsMock() bool {
	return true
}

func (m *MockCommandRunner) ensureNatStateLocked() {
	if m.ChainSpoofIPs == nil {
		m.ChainSpoofIPs = make(map[string]string)
	}
	if m.NatChains == nil {
		m.NatChains = make(map[string][]string)
	}
}

func (m *MockCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureNatStateLocked()
	m.Calls = append(m.Calls, MockCommandCall{Name: name, Args: append([]string(nil), args...)})

	cmdLine := name + " " + strings.Join(args, " ")
	if name == "ip" && strings.Contains(cmdLine, "route get") {
		if m.RouteFail {
			return []byte("RTNETLINK answers: Network is unreachable"), 2, nil
		}
		target := ""
		if len(args) >= 3 {
			target = args[2]
		}
		if m.RouteTable != nil {
			if customOut, ok := m.RouteTable[target]; ok {
				return []byte(customOut), 0, nil
			}
		}
		if target == "" {
			target = "127.0.0.1"
		}
		return []byte(fmt.Sprintf("%s via 10.0.0.1 dev eth0 src 10.0.0.15 uid 0", target)), 0, nil
	}

	if name == "iptables" {
		if m.PermFail {
			return []byte("iptables: Permission denied (you must be root)."), 4, context.DeadlineExceeded
		}

		// Parse -t nat operations to maintain stateful simulated NAT table
		if len(args) >= 4 && args[0] == "-t" && args[1] == "nat" {
			op := args[2]
			targetChain := args[3]

			switch op {
			case "-N":
				if _, exists := m.NatChains[targetChain]; exists {
					return []byte("iptables: Chain already exists."), 1, errors.New("chain already exists")
				}
				m.NatChains[targetChain] = []string{}
				return []byte(""), 0, nil

			case "-A":
				if m.FailOnAppend {
					return []byte("iptables: simulated rule append failure"), 1, errors.New("simulated append error")
				}
				ruleStr := strings.Join(args[4:], " ")
				m.NatChains[targetChain] = append(m.NatChains[targetChain], ruleStr)
				for i, arg := range args {
					if arg == "--to-source" && i+1 < len(args) {
						m.LastSpoofIP = args[i+1]
						m.ChainSpoofIPs[targetChain] = args[i+1]
					}
				}
				return []byte(""), 0, nil

			case "-I":
				if targetChain == "POSTROUTING" {
					if m.FailOnPostInsert {
						return []byte("iptables: simulated POSTROUTING insert failure"), 1, errors.New("simulated insert error")
					}
					jumpRule := strings.Join(args[5:], " ")
					m.PostroutingRules = append([]string{jumpRule}, m.PostroutingRules...)
				}
				return []byte(""), 0, nil

			case "-D":
				if targetChain == "POSTROUTING" {
					jumpRule := strings.Join(args[4:], " ")
					filtered := make([]string, 0, len(m.PostroutingRules))
					removed := false
					for _, r := range m.PostroutingRules {
						if !removed && r == jumpRule {
							removed = true
							continue
						}
						filtered = append(filtered, r)
					}
					m.PostroutingRules = filtered
				}
				return []byte(""), 0, nil

			case "-F":
				if _, exists := m.NatChains[targetChain]; exists {
					m.NatChains[targetChain] = []string{}
				}
				return []byte(""), 0, nil

			case "-X":
				delete(m.NatChains, targetChain)
				delete(m.ChainSpoofIPs, targetChain)
				return []byte(""), 0, nil

			case "-L":
				spoof := m.ChainSpoofIPs[targetChain]
				if spoof == "" {
					spoof = m.LastSpoofIP
				}
				if spoof == "" {
					spoof = "8.8.8.8"
				}
				out := fmt.Sprintf("Chain %s (1 references)\n"+
					"    pkts      bytes target     prot opt in     out     source               destination\n"+
					"       3      252 SNAT       all  --  *      eth0    0.0.0.0/0            127.0.0.1            to:%s\n", targetChain, spoof)
				return []byte(out), 0, nil
			}
		}
		return []byte(""), 0, nil
	}

	if name == "ping" {
		return []byte("1 packets transmitted, 0 received, 100% packet loss"), 1, nil
	}

	return []byte(""), 0, nil
}

func (m *MockCommandRunner) HasChain(chainName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.NatChains[chainName]
	return ok
}

func (m *MockCommandRunner) HasPostroutingJumpTo(chainName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	suffix := "-j " + chainName
	for _, r := range m.PostroutingRules {
		if strings.HasSuffix(r, suffix) || strings.Contains(r, suffix+" ") {
			return true
		}
	}
	return false
}

func findFreeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	_ = ln.Close()
	return port
}

type trackedPacketConn struct {
	net.PacketConn
	closeOnce   sync.Once
	closedCount *int32
}

func (c *trackedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		atomic.AddInt32(c.closedCount, 1)
		err = c.PacketConn.Close()
	})
	return err
}

type ControlledStartupBinder struct {
	bindEntered chan struct{}
	bindRelease chan struct{}
	closedCount int32
}

func (b *ControlledStartupBinder) ListenUDP(_ context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	rawConn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	tc := &trackedPacketConn{PacketConn: rawConn, closedCount: &b.closedCount}
	if b.bindEntered != nil {
		close(b.bindEntered)
	}
	if b.bindRelease != nil {
		<-b.bindRelease
	}
	return tc, nil
}

func (b *ControlledStartupBinder) ListenICMP(ctx context.Context, network, address string) (net.PacketConn, error) {
	real := &RealListenerBinder{}
	return real.ListenICMP(ctx, network, address)
}

// 1. Test UDP Cryptographic Packet Validation & Replay/Tamper Rejection
func TestUDPPacketVerification(t *testing.T) {
	secret := randomHex(16)
	sessionID := randomHex(16)
	nonce := randomHex(16)
	now := time.Now().UnixMilli()

	validPayload := BuildUDPPacketPayload(secret, sessionID, nonce, 2, now)
	seq, err := ValidateUDPPacketPayload(validPayload, secret, sessionID, nonce, 5)
	if err != nil || seq != 2 {
		t.Fatalf("expected valid UDP packet seq=2, got seq=%d, err=%v", seq, err)
	}

	tampered := bytes.Replace(validPayload, []byte("|udp|2|"), []byte("|udp|3|"), 1)
	if _, err := ValidateUDPPacketPayload(tampered, secret, sessionID, nonce, 5); err == nil {
		t.Fatal("expected HMAC failure on tampered sequence number")
	}

	if _, err := ValidateUDPPacketPayload(validPayload, secret, randomHex(16), nonce, 5); err == nil {
		t.Fatal("expected session ID mismatch error")
	}

	stalePayload := BuildUDPPacketPayload(secret, sessionID, nonce, 1, time.Now().Add(-5*time.Minute).UnixMilli())
	if _, err := ValidateUDPPacketPayload(stalePayload, secret, sessionID, nonce, 5); err == nil {
		t.Fatal("expected replay protection error for stale timestamp")
	}
}

// 2. Test ICMP Cryptographic Binary Frame & Raw ICMP Packet Validation
func TestICMPPacketVerification(t *testing.T) {
	secret := randomHex(16)
	sessionID := randomHex(16)
	nonce := randomHex(16)

	patHex, err := BuildICMPPatternHex(secret, sessionID, nonce, 3)
	if err != nil || len(patHex) != 32 {
		t.Fatalf("expected 32-char hex pattern, got len=%d, err=%v", len(patHex), err)
	}
	patBytes, _ := hex.DecodeString(patHex)

	icmpPkt := make([]byte, 8+16+32)
	icmpPkt[0] = 8
	icmpPkt[1] = 0
	binary.BigEndian.PutUint16(icmpPkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmpPkt[6:8], 1)
	copy(icmpPkt[24:40], patBytes)
	copy(icmpPkt[40:56], patBytes)

	seq, icmpID, icmpSeq, err := ValidateICMPRawPacket(icmpPkt, secret, sessionID, nonce, 5)
	if err != nil {
		t.Fatalf("expected valid ICMP packet, got err=%v", err)
	}
	if seq != 3 || icmpID != 0x1234 || icmpSeq != 1 {
		t.Fatalf("unexpected ICMP fields: seq=%d, id=%x, icmpSeq=%d", seq, icmpID, icmpSeq)
	}

	icmpPkt[0] = 0
	if _, _, _, err := ValidateICMPRawPacket(icmpPkt, secret, sessionID, nonce, 5); err == nil {
		t.Fatal("expected rejection for ICMP Echo Reply (Type 0)")
	}
}

// 3. Test Isolated SNAT Chain Creation, Process/Session Scoping, Counter Parsing & Cleanup
func TestIsolatedSNATChainLifecycle(t *testing.T) {
	mockRunner := &MockCommandRunner{}
	srv, err := NewAppServer(mockRunner)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	iso, err := srv.SetupIsolatedSNATChain(ctx, "a1b2c3d4", "eth0", "127.0.0.1", "8.8.8.8", "icmp", 0)
	if err != nil {
		t.Fatalf("SetupIsolatedSNATChain failed: %v", err)
	}
	expectedChain := fmt.Sprintf("CSPF_%s_A1B2C3D4", srv.InstanceChainID)
	if iso.ChainName != expectedChain {
		t.Fatalf("expected process+session scoped chain name %s, got %s", expectedChain, iso.ChainName)
	}
	if len(iso.ChainName) > 28 {
		t.Fatalf("chain name %s exceeds Linux 28-char iptables limit", iso.ChainName)
	}

	pkts, bCount, _, err := iso.ReadCounters(ctx)
	if err != nil || pkts != 3 || bCount != 252 {
		t.Fatalf("expected pkts=3, bytes=252, got pkts=%d, bytes=%d, err=%v", pkts, bCount, err)
	}

	iso.Cleanup()

	if mockRunner.HasChain(expectedChain) {
		t.Fatalf("expected chain %s to be deleted after Cleanup()", expectedChain)
	}
	if mockRunner.HasPostroutingJumpTo(expectedChain) {
		t.Fatalf("expected POSTROUTING jump to %s to be deleted after Cleanup()", expectedChain)
	}
}

// 4. Test Multi-Session & Multi-Process SNAT Chain Isolation:
// Proves that cleaning up one session or one CheckSpoof process NEVER deletes
// another active session's SNAT chains, jump rules, or unrelated firewall rules.
func TestSNATChainIsolation_PreservesOtherSessionsAndProcesses(t *testing.T) {
	sharedKernelNAT := &MockCommandRunner{
		NatChains: map[string][]string{
			"DOCKER":              {"-o docker0 -j MASQUERADE"},
			"CSPF_FOREIGN_999999": {"-o eth0 -d 198.51.100.1 -p udp --dport 5555 -j SNAT --to-source 1.1.1.1"},
		},
		PostroutingRules: []string{
			"-o docker0 -j DOCKER",
			"-o eth0 -d 198.51.100.1 -p udp --dport 5555 -j CSPF_FOREIGN_999999",
		},
	}

	srv1, err := NewAppServer(sharedKernelNAT)
	if err != nil {
		t.Fatal(err)
	}
	srv2, err := NewAppServer(sharedKernelNAT)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Create two concurrent sessions on srv1 and one active session on srv2
	iso1A, err := srv1.SetupIsolatedSNATChain(ctx, "1111aaaa", "eth0", "203.0.113.10", "8.8.8.8", "icmp", 0)
	if err != nil {
		t.Fatalf("srv1 session A setup failed: %v", err)
	}
	iso1B, err := srv1.SetupIsolatedSNATChain(ctx, "2222bbbb", "eth0", "203.0.113.10", "9.9.9.9", "udp", 5555)
	if err != nil {
		t.Fatalf("srv1 session B setup failed: %v", err)
	}
	iso2A, err := srv2.SetupIsolatedSNATChain(ctx, "1111aaaa", "eth0", "203.0.113.20", "1.1.1.1", "icmp", 0)
	if err != nil {
		t.Fatalf("srv2 session A setup failed: %v", err)
	}

	if iso1A.ChainName == iso1B.ChainName || iso1A.ChainName == iso2A.ChainName {
		t.Fatalf("expected unique chain names across sessions and processes, got %s, %s, %s",
			iso1A.ChainName, iso1B.ChainName, iso2A.ChainName)
	}

	// Step A: Clean up Session 1A on srv1. Session 1B, srv2's Session 2A, CSPF_FOREIGN_999999, and DOCKER must remain intact.
	iso1A.Cleanup()
	// Repeated Cleanup() must be a safe no-op
	iso1A.Cleanup()

	if sharedKernelNAT.HasChain(iso1A.ChainName) || sharedKernelNAT.HasPostroutingJumpTo(iso1A.ChainName) {
		t.Fatalf("expected iso1A (%s) to be removed", iso1A.ChainName)
	}
	if !sharedKernelNAT.HasChain(iso1B.ChainName) || !sharedKernelNAT.HasPostroutingJumpTo(iso1B.ChainName) {
		t.Fatalf("cleaning up iso1A broke active sibling session iso1B (%s)!", iso1B.ChainName)
	}
	if !sharedKernelNAT.HasChain(iso2A.ChainName) || !sharedKernelNAT.HasPostroutingJumpTo(iso2A.ChainName) {
		t.Fatalf("cleaning up iso1A broke another process's active session iso2A (%s)!", iso2A.ChainName)
	}
	if !sharedKernelNAT.HasChain("CSPF_FOREIGN_999999") || !sharedKernelNAT.HasPostroutingJumpTo("CSPF_FOREIGN_999999") {
		t.Fatal("cleaning up iso1A deleted an unowned CSPF_FOREIGN_999999 chain!")
	}
	if !sharedKernelNAT.HasChain("DOCKER") || !sharedKernelNAT.HasPostroutingJumpTo("DOCKER") {
		t.Fatal("cleaning up iso1A deleted unrelated DOCKER firewall rules!")
	}

	// Step B: Call srv1.CleanupAllChains() (e.g. srv1 shutting down).
	// Must remove srv1's remaining iso1B, but MUST NOT touch srv2's iso2A, CSPF_FOREIGN_999999, or DOCKER.
	srv1.CleanupAllChains()

	if sharedKernelNAT.HasChain(iso1B.ChainName) || sharedKernelNAT.HasPostroutingJumpTo(iso1B.ChainName) {
		t.Fatalf("expected srv1.CleanupAllChains() to remove iso1B (%s)", iso1B.ChainName)
	}
	if !sharedKernelNAT.HasChain(iso2A.ChainName) || !sharedKernelNAT.HasPostroutingJumpTo(iso2A.ChainName) {
		t.Fatalf("srv1.CleanupAllChains() deleted srv2's active chain %s!", iso2A.ChainName)
	}
	if !sharedKernelNAT.HasChain("CSPF_FOREIGN_999999") || !sharedKernelNAT.HasPostroutingJumpTo("CSPF_FOREIGN_999999") {
		t.Fatal("srv1.CleanupAllChains() deleted foreign CSPF_FOREIGN_999999 chain!")
	}
	if !sharedKernelNAT.HasChain("DOCKER") || !sharedKernelNAT.HasPostroutingJumpTo("DOCKER") {
		t.Fatal("srv1.CleanupAllChains() deleted unrelated DOCKER chain!")
	}

	// Step C: Clean up srv2
	srv2.CleanupAllChains()
	if sharedKernelNAT.HasChain(iso2A.ChainName) || sharedKernelNAT.HasPostroutingJumpTo(iso2A.ChainName) {
		t.Fatalf("expected srv2.CleanupAllChains() to remove iso2A (%s)", iso2A.ChainName)
	}
	if !sharedKernelNAT.HasChain("CSPF_FOREIGN_999999") || !sharedKernelNAT.HasChain("DOCKER") {
		t.Fatal("srv2.CleanupAllChains() deleted unowned chains!")
	}
}

// 5. Test Partial Initialization Rollback & Crash Journal Recovery
func TestSNATChainPartialInitAndCrashJournalRecovery(t *testing.T) {
	mockNAT := &MockCommandRunner{}
	srv, err := NewAppServer(mockNAT)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Create a healthy active session first
	activeIso, err := srv.SetupIsolatedSNATChain(ctx, "active01", "eth0", "203.0.113.10", "8.8.8.8", "icmp", 0)
	if err != nil {
		t.Fatalf("failed to create activeIso: %v", err)
	}

	// Simulate failure during POSTROUTING jump insertion (-N and -A succeed, -I fails)
	mockNAT.FailOnPostInsert = true
	_, err = srv.SetupIsolatedSNATChain(ctx, "partfail", "eth0", "203.0.113.10", "1.1.1.1", "icmp", 0)
	if err == nil {
		t.Fatal("expected SetupIsolatedSNATChain to fail when POSTROUTING insert fails")
	}
	mockNAT.FailOnPostInsert = false

	failedChain := srv.BuildSNATChainName("partfail")
	if mockNAT.HasChain(failedChain) || mockNAT.HasPostroutingJumpTo(failedChain) {
		t.Fatalf("partial initialization did not roll back chain %s", failedChain)
	}
	if !mockNAT.HasChain(activeIso.ChainName) || !mockNAT.HasPostroutingJumpTo(activeIso.ChainName) {
		t.Fatalf("partial initialization rollback disturbed active session %s!", activeIso.ChainName)
	}

	// Test crash journal recovery: dead PID entry is cleaned up while live PID entry (os.Getpid()) is preserved
	tmpJournal := filepath.Join(t.TempDir(), "cspf_journal.json")
	srv.JournalPath = tmpJournal

	deadChain := "CSPF_DEAD01_CAFEBABE"
	deadJump := []string{"-o", "eth0", "-d", "203.0.113.55", "-p", "icmp", "-j", deadChain}
	mockNAT.mu.Lock()
	mockNAT.NatChains[deadChain] = []string{"-o eth0 -j SNAT --to-source 9.9.9.9"}
	mockNAT.PostroutingRules = append(mockNAT.PostroutingRules, strings.Join(deadJump, " "))
	mockNAT.mu.Unlock()

	journalEntries := []CrashJournalEntry{
		{
			PID:          999999, // Dead/non-existent PID
			InstanceID:   "DEAD01",
			SessionID:    "cafebabe",
			ChainName:    deadChain,
			JumpArgs:     deadJump,
			ChainCreated: true,
			RuleAdded:    true,
			JumpInserted: true,
		},
		{
			PID:          os.Getpid(), // Live current process PID
			InstanceID:   srv.InstanceChainID,
			SessionID:    "active01",
			ChainName:    activeIso.ChainName,
			JumpArgs:     activeIso.JumpArgs,
			ChainCreated: true,
			RuleAdded:    true,
			JumpInserted: true,
		},
	}
	rawJournal, _ := json.Marshal(journalEntries)
	if err := os.WriteFile(tmpJournal, rawJournal, 0600); err != nil {
		t.Fatal(err)
	}

	recovered := srv.RecoverOrphanedChainsFromJournal(ctx)
	if recovered != 1 {
		t.Fatalf("expected 1 dead-PID chain to be recovered, got %d", recovered)
	}
	if mockNAT.HasChain(deadChain) || mockNAT.HasPostroutingJumpTo(deadChain) {
		t.Fatalf("expected dead-PID chain %s to be cleaned up", deadChain)
	}
	if !mockNAT.HasChain(activeIso.ChainName) || !mockNAT.HasPostroutingJumpTo(activeIso.ChainName) {
		t.Fatalf("journal recovery deleted live-PID chain %s!", activeIso.ChainName)
	}

	activeIso.Cleanup()
}

// 6. Test Loopback & Mocked Firewall Control Flow:
// Verifies TLS pairing, receiver readiness, and packet framing, AND proves that
// loopback (127.0.0.1) or mocked iptables NEVER falsely reports SPOOF_SUCCESS.
func TestLocalControlFlowAndPacketFraming_LoopbackMocked_DoesNotClaimSpoofSuccess(t *testing.T) {
	runnerA := &MockCommandRunner{}
	runnerB := &MockCommandRunner{}

	srvA, err := NewAppServer(runnerA)
	if err != nil {
		t.Fatal(err)
	}
	defer srvA.Shutdown()

	srvB, err := NewAppServer(runnerB)
	if err != nil {
		t.Fatal(err)
	}
	defer srvB.Shutdown()

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()
	_, portA, _ := net.SplitHostPort(lnA.Addr().String())
	srvA.ServerIP = "127.0.0.1"
	srvA.Port = portA

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()
	_, portB, _ := net.SplitHostPort(lnB.Addr().String())
	srvB.ServerIP = "127.0.0.1"
	srvB.Port = portB

	go func() { _ = serveMultiplexed(lnA, srvA.TLSCert, srvA.Routes()) }()
	go func() { _ = serveMultiplexed(lnB, srvB.TLSCert, srvB.Routes()) }()

	reqTestEarly, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/test", strings.NewReader(`{}`))
	reqTestEarly.Header.Set("X-Admin-Key", srvA.AdminKey)
	respEarly, err := http.DefaultClient.Do(reqTestEarly)
	if err != nil || respEarly.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 Precondition Failed before readiness, got %v", respEarly)
	}
	_ = respEarly.Body.Close()

	tokenB := srvB.PairingToken()
	pairBody, _ := json.Marshal(map[string]string{"remote_token": tokenB})
	reqPair, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/pair", bytes.NewReader(pairBody))
	reqPair.Header.Set("X-Admin-Key", srvA.AdminKey)
	respPair, err := http.DefaultClient.Do(reqPair)
	if err != nil || respPair.StatusCode != http.StatusOK {
		t.Fatalf("pairing failed: err=%v, status=%v", err, respPair)
	}
	_ = respPair.Body.Close()

	srvB.mu.RLock()
	initialRecvState := srvB.LocalReceiverState
	srvB.mu.RUnlock()
	if initialRecvState != RecvIdle {
		t.Fatalf("expected Server B receiver state to remain IDLE after pairing, got %s", initialRecvState)
	}

	prepBody, _ := json.Marshal(map[string]interface{}{
		"spoof_ip":     "127.0.0.1",
		"test_type":    "udp",
		"packet_count": 3,
	})
	reqPrep, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/prepare", bytes.NewReader(prepBody))
	reqPrep.Header.Set("X-Admin-Key", srvA.AdminKey)
	respPrep, err := http.DefaultClient.Do(reqPrep)
	if err != nil || respPrep.StatusCode != http.StatusOK {
		t.Fatalf("prepare receiver failed: err=%v, status=%v", err, respPrep)
	}
	_ = respPrep.Body.Close()

	srvB.mu.RLock()
	bState := srvB.LocalReceiverState
	srvB.mu.RUnlock()
	if bState != RecvReady {
		t.Fatalf("expected Server B state READY_TO_RECEIVE, got %s", bState)
	}

	reqRun, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/test", strings.NewReader(`{}`))
	reqRun.Header.Set("X-Admin-Key", srvA.AdminKey)
	respRun, err := http.DefaultClient.Do(reqRun)
	if err != nil || respRun.StatusCode != http.StatusOK {
		t.Fatalf("test execution failed: err=%v, status=%v", err, respRun)
	}
	defer respRun.Body.Close()

	var testRes AdminTestResult
	if err := json.NewDecoder(respRun.Body).Decode(&testRes); err != nil {
		t.Fatal(err)
	}

	if !testRes.ReceiverListenerReady || !testRes.SNATRuleInstalled || !testRes.LocalPacketGenSuccess {
		t.Fatalf("expected local & readiness stages to succeed, got ready=%v, snat=%v, localGen=%v",
			testRes.ReceiverListenerReady, testRes.SNATRuleInstalled, testRes.LocalPacketGenSuccess)
	}

	if testRes.PrimaryClassification == ClassSpoofSuccess || testRes.RemoteSpoofVerified {
		t.Fatalf("SECURITY/VERIFICATION BUG: loopback or mocked test falsely reported SPOOF_SUCCESS! got classification=%s, RemoteSpoofVerified=%v",
			testRes.PrimaryClassification, testRes.RemoteSpoofVerified)
	}
	if testRes.PrimaryClassification != ClassSimulatedControlVerified || !testRes.IsLoopbackOrSimulated {
		t.Fatalf("expected SIMULATED_CONTROL_FLOW_VERIFIED with IsLoopbackOrSimulated=true, got %s (isLoopback=%v)",
			testRes.PrimaryClassification, testRes.IsLoopbackOrSimulated)
	}
}

// 7. Test Genuine Spoof Setup Guard (Rejects Loopback, Mock Runner, LocalOutboundIP, and PublicIP)
func TestGenuineSpoofSetupGuard(t *testing.T) {
	srvMock, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	srvMock.ServerIP = "198.51.100.10"
	if ok, _ := srvMock.isGenuineNetworkSpoofSetup("203.0.113.20", "8.8.8.8"); ok {
		t.Fatal("expected MockCommandRunner to be rejected as non-genuine network spoof setup")
	}

	srvReal, err := NewAppServer(&RealCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	srvReal.LocalOutboundIP = "10.0.0.15"
	srvReal.PublicIP = "198.51.100.10"
	srvReal.ServerIP = "198.51.100.10"

	if ok, _ := srvReal.isGenuineNetworkSpoofSetup("127.0.0.1", "8.8.8.8"); ok {
		t.Fatal("expected loopback target 127.0.0.1 to be rejected")
	}
	if ok, _ := srvReal.isGenuineNetworkSpoofSetup("203.0.113.20", "127.0.0.1"); ok {
		t.Fatal("expected loopback spoof IP 127.0.0.1 to be rejected")
	}
	if ok, _ := srvReal.isGenuineNetworkSpoofSetup("203.0.113.20", "198.51.100.10"); ok {
		t.Fatal("expected unspoofed IP matching sender PublicIP to be rejected")
	}
	if ok, _ := srvReal.isGenuineNetworkSpoofSetup("203.0.113.20", "10.0.0.15"); ok {
		t.Fatal("expected unspoofed IP matching sender LocalOutboundIP to be rejected")
	}
	if ok, _ := srvReal.isGenuineNetworkSpoofSetup("203.0.113.20", "172.16.0.9", "172.16.0.9"); ok {
		t.Fatal("expected unspoofed IP matching route source IP to be rejected")
	}

	if ok, reason := srvReal.isGenuineNetworkSpoofSetup("203.0.113.20", "8.8.8.8", "10.0.0.15"); !ok {
		t.Fatalf("expected valid two-VPS setup to pass guard, got rejection: %s", reason)
	}
}

// 8. Test Route Selection & `ip route get` Parsing (Outgoing Interface + Source IP)
func TestParseIPRouteGetOutput_AndDestinationRouteSelection(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantDev  string
		wantSrc  string
		wantGW   string
		wantDest string
		wantErr  bool
	}{
		{
			name:     "Standard NAT gateway route",
			raw:      "8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.15 uid 0 \n    cache",
			wantDev:  "eth0",
			wantSrc:  "10.0.0.15",
			wantGW:   "10.0.0.1",
			wantDest: "8.8.8.8",
		},
		{
			name:     "Direct subnet route without gateway",
			raw:      "192.168.50.20 dev ens160 src 192.168.50.5 uid 0",
			wantDev:  "ens160",
			wantSrc:  "192.168.50.5",
			wantGW:   "",
			wantDest: "192.168.50.20",
		},
		{
			name:     "Policy routing table with WireGuard interface",
			raw:      "203.0.113.88 via 10.99.0.1 dev wg0 table 51820 src 10.99.0.2 uid 0",
			wantDev:  "wg0",
			wantSrc:  "10.99.0.2",
			wantGW:   "10.99.0.1",
			wantDest: "203.0.113.88",
		},
		{
			name:    "Missing src address must fail",
			raw:     "8.8.8.8 via 10.0.0.1 dev eth0",
			wantErr: true,
		},
		{
			name:    "Missing dev interface must fail",
			raw:     "RTNETLINK answers: Network is unreachable",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseIPRouteGetOutput(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got %+v", tc.raw, info)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Interface != tc.wantDev || info.SourceIP != tc.wantSrc || info.Gateway != tc.wantGW || info.Destination != tc.wantDest {
				t.Fatalf("mismatch: got %+v, want dev=%s src=%s gw=%s dest=%s",
					info, tc.wantDev, tc.wantSrc, tc.wantGW, tc.wantDest)
			}
		})
	}

	mockRunner := &MockCommandRunner{
		RouteTable: map[string]string{
			"8.8.8.8":      "8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.15 uid 0",
			"203.0.113.99": "203.0.113.99 via 172.16.0.1 dev ens192 src 172.16.0.44 uid 0",
		},
	}
	srv, err := NewAppServer(mockRunner)
	if err != nil {
		t.Fatal(err)
	}
	rInfo, err := srv.ResolveRoute(context.Background(), "203.0.113.99")
	if err != nil {
		t.Fatalf("ResolveRoute failed: %v", err)
	}
	if rInfo.Interface != "ens192" || rInfo.SourceIP != "172.16.0.44" {
		t.Fatalf("expected destination route dev=ens192 src=172.16.0.44, got %+v", rInfo)
	}
}

// 9. Test Private, CGNAT, Loopback, and Public IPv4 Classification
func TestPrivateAndReservedIPv4Classification(t *testing.T) {
	privateOrReserved := []string{
		"127.0.0.1",
		"10.0.0.15",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.10",
		"100.64.0.1",
		"100.127.255.254",
		"169.254.10.20",
		"0.0.0.0",
		"255.255.255.255",
		"not-an-ip",
	}
	for _, ip := range privateOrReserved {
		if IsPublicRoutableIPv4(ip) {
			t.Fatalf("expected %s to NOT be classified as a public routable IPv4", ip)
		}
	}

	publicRoutable := []string{
		"8.8.8.8",
		"1.1.1.1",
		"94.184.6.138",
		"203.0.113.50",
		"100.63.255.254",
		"100.128.0.1",
	}
	for _, ip := range publicRoutable {
		if !IsPublicRoutableIPv4(ip) {
			t.Fatalf("expected %s to be classified as a public routable IPv4", ip)
		}
	}
}

// 10. Test Public IP Detection, NAT Separation, UNKNOWN Fallback, and Manual Public IP Configuration
func TestPublicIPDetection_NAT_Unknown_AndManualOverride(t *testing.T) {
	_ = os.Unsetenv("PUBLIC_IP")

	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if srv.LocalOutboundIP != "10.0.0.15" || srv.LocalInterface != "eth0" {
		t.Fatalf("expected LocalOutboundIP=10.0.0.15 on eth0, got %s on %s", srv.LocalOutboundIP, srv.LocalInterface)
	}
	if srv.PublicIP != IPValueUnknown || srv.PublicIPSource != PublicIPSourceNone {
		t.Fatalf("expected PublicIP=UNKNOWN when not discovered, got %s (%s)", srv.PublicIP, srv.PublicIPSource)
	}
	if !srv.BehindNAT {
		t.Fatal("expected BehindNAT=true when LocalOutboundIP is RFC1918 10.0.0.15")
	}

	ep1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.10\n"))
	}))
	defer ep1.Close()
	ep2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.22\n"))
	}))
	defer ep2.Close()

	srv.PublicIPEndpoints = []string{ep1.URL, ep2.URL}
	srv.PublicIPHTTP = ep1.Client()
	gotIP, err := srv.DiscoverAndSetPublicIP(context.Background())
	if err == nil || gotIP != IPValueUnknown || srv.PublicIP != IPValueUnknown {
		t.Fatalf("expected conflicting discovery responses to report UNKNOWN, got ip=%s, srv.PublicIP=%s, err=%v",
			gotIP, srv.PublicIP, err)
	}

	epPrivate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.168.1.250"))
	}))
	defer epPrivate.Close()
	srv.PublicIPEndpoints = []string{epPrivate.URL}
	gotIP, err = srv.DiscoverAndSetPublicIP(context.Background())
	if err == nil || gotIP != IPValueUnknown || srv.PublicIP != IPValueUnknown {
		t.Fatalf("expected private IP from discovery endpoint to be rejected as UNKNOWN, got %s (err=%v)", gotIP, err)
	}

	epConsistent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.10\n"))
	}))
	defer epConsistent.Close()
	srv.PublicIPEndpoints = []string{ep1.URL, epConsistent.URL}
	gotIP, err = srv.DiscoverAndSetPublicIP(context.Background())
	if err != nil || gotIP != "203.0.113.10" {
		t.Fatalf("expected discovered public IP 203.0.113.10, got %s (err=%v)", gotIP, err)
	}
	if srv.LocalOutboundIP != "10.0.0.15" || srv.PublicIP != "203.0.113.10" || srv.PublicIPSource != PublicIPDiscovered || !srv.BehindNAT {
		t.Fatalf("unexpected NAT state after discovery: local=%s, public=%s (%s), behindNAT=%v",
			srv.LocalOutboundIP, srv.PublicIP, srv.PublicIPSource, srv.BehindNAT)
	}

	if err := srv.SetManualPublicIP("10.0.0.99"); err == nil {
		t.Fatal("expected SetManualPublicIP to reject private RFC1918 IP 10.0.0.99")
	}
	if err := srv.SetManualPublicIP("127.0.0.1"); err == nil {
		t.Fatal("expected SetManualPublicIP to reject loopback IP 127.0.0.1")
	}
	if err := srv.SetManualPublicIP("94.184.6.138"); err != nil {
		t.Fatalf("expected SetManualPublicIP to accept valid public IP, got err=%v", err)
	}
	if srv.PublicIP != "94.184.6.138" || srv.PublicIPSource != PublicIPManual {
		t.Fatalf("expected manual PublicIP=94.184.6.138 (MANUAL), got %s (%s)", srv.PublicIP, srv.PublicIPSource)
	}
	if !strings.HasPrefix(srv.PairingToken(), "94.184.6.138:") {
		t.Fatalf("expected PairingToken to use configured PublicIP, got %s", srv.PairingToken())
	}
}

// 11. Real Two-Server VPS Integration Test Mode
func TestRealTwoServerVPSIntegration(t *testing.T) {
	peerToken := strings.TrimSpace(os.Getenv("CHECKSPOOF_PEER_TOKEN"))
	spoofIP := strings.TrimSpace(os.Getenv("CHECKSPOOF_SPOOF_IP"))
	method := strings.TrimSpace(os.Getenv("CHECKSPOOF_METHOD"))

	if peerToken == "" {
		t.Skip("Skipping real two-VPS integration test: set CHECKSPOOF_PEER_TOKEN and CHECKSPOOF_SPOOF_IP to run against a live remote receiver VPS.")
	}
	if spoofIP == "" {
		spoofIP = "8.8.8.8"
	}
	if method == "" {
		method = "udp"
	}

	srv, err := NewAppServer(&RealCommandRunner{})
	if err != nil {
		t.Fatalf("failed to initialize real AppServer: %v", err)
	}
	srv.Port = "8085"
	defer srv.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	res, err := srv.RunRealVPSIntegrationTest(ctx, peerToken, spoofIP, method, 3)
	if err != nil {
		t.Fatalf("real two-VPS integration test failed: %v", err)
	}

	t.Logf("Stage 1 [ReceiverListenerReady] : %v", res.ReceiverListenerReady)
	t.Logf("Stage 2 [SNATRuleInstalled]     : %v (Chain=%s, Iface=%s, Src=%s)", res.SNATRuleInstalled, res.IsolatedChainName, res.OutgoingInterface, res.OutgoingSourceIP)
	t.Logf("Stage 3 [LocalPacketGenSuccess] : %v (%d/%d sent)", res.LocalPacketGenSuccess, res.PacketsSent, res.PacketsAttempted)
	t.Logf("Stage 4 [SNATPacketsMatched]    : %d pkts (%d bytes)", res.SNATPacketsMatched, res.SNATBytesMatched)
	t.Logf("Stage 5 [RemoteSpoofVerified]   : %v (%d verified packets arriving with source IP %s)", res.RemoteSpoofVerified, res.RemoteVerifiedCount, spoofIP)
	t.Logf("Final Verdict                   : %s — %s", res.PrimaryClassification, res.ConfirmedEvidence)

	if res.IsLoopbackOrSimulated {
		t.Fatalf("real VPS integration test must not use loopback or simulated runner: %s", res.ConfirmedEvidence)
	}
	if !res.ReceiverListenerReady || !res.SNATRuleInstalled || !res.LocalPacketGenSuccess {
		t.Fatalf("local sender or remote listener setup failed: %+v", res)
	}
}

// 12. Regression Test (Case A): Replacing an active receiver session must not deadlock
func TestRegression_ReplaceActiveReceiverSession_NoDeadlock(t *testing.T) {
	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	udpPort := findFreeUDPPort(t)
	req1 := PeerPrepareRequest{
		SessionID:        randomHex(16),
		Nonce:            randomHex(16),
		ExpectedSourceIP: "127.0.0.1",
		TestType:         "udp",
		UDPPort:          udpPort,
		MaxPackets:       3,
		TimeoutSec:       30,
	}

	resp1, err := srv.StartReceiverSession(req1, srv.PairingSecret)
	if err != nil || resp1.ReceiverState != RecvReady {
		t.Fatalf("first StartReceiverSession failed: resp=%v, err=%v", resp1, err)
	}

	srv.mu.RLock()
	sess1 := srv.ActiveRecvSession
	srv.mu.RUnlock()
	if sess1 == nil || sess1.SessionID != req1.SessionID {
		t.Fatal("sess1 not registered as active session")
	}

	done := make(chan error, 1)
	var lastSessID string
	go func() {
		for i := 0; i < 4; i++ {
			nextReq := PeerPrepareRequest{
				SessionID:        randomHex(16),
				Nonce:            randomHex(16),
				ExpectedSourceIP: "127.0.0.1",
				TestType:         "udp",
				UDPPort:          udpPort,
				MaxPackets:       3,
				TimeoutSec:       30,
			}
			lastSessID = nextReq.SessionID
			resp, rErr := srv.StartReceiverSession(nextReq, srv.PairingSecret)
			if rErr != nil {
				done <- rErr
				return
			}
			if resp.ReceiverState != RecvReady {
				done <- fmt.Errorf("expected READY_TO_RECEIVE, got %s", resp.ReceiverState)
				return
			}
		}
		done <- nil
	}()

	select {
	case rErr := <-done:
		if rErr != nil {
			t.Fatalf("session replacement failed: %v", rErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK DETECTED: StartReceiverSession hung when replacing an active receiver session")
	}

	select {
	case <-sess1.DoneChan:
	default:
		t.Fatal("expected sess1.DoneChan to be closed after replacement")
	}
	if st := sess1.GetState(); st != RecvCompleted {
		t.Fatalf("expected sess1 state RecvCompleted, got %s", st)
	}

	srv.mu.RLock()
	activeSess := srv.ActiveRecvSession
	serverRecvState := srv.LocalReceiverState
	srv.mu.RUnlock()

	if activeSess == nil || activeSess.SessionID != lastSessID {
		t.Fatalf("expected active session %s, got %v", lastSessID, activeSess)
	}
	if serverRecvState != RecvReady {
		t.Fatalf("expected server LocalReceiverState READY_TO_RECEIVE, got %s", serverRecvState)
	}
}

// 13. Regression Test (Case B): Concurrent StartReceiverSession calls must serialize cleanly
func TestRegression_ConcurrentStartReceiverSession(t *testing.T) {
	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	udpPort := findFreeUDPPort(t)
	const workers = 8
	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier
			req := PeerPrepareRequest{
				SessionID:        randomHex(16),
				Nonce:            randomHex(16),
				ExpectedSourceIP: "127.0.0.1",
				TestType:         "udp",
				UDPPort:          udpPort,
				MaxPackets:       3,
				TimeoutSec:       30,
			}
			resp, sErr := srv.StartReceiverSession(req, srv.PairingSecret)
			if sErr != nil {
				errs <- sErr
				return
			}
			if resp.ReceiverState != RecvReady {
				errs <- fmt.Errorf("unexpected state: %s", resp.ReceiverState)
			}
		}()
	}

	close(startBarrier)

	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK DETECTED during simultaneous StartReceiverSession calls")
	}
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent StartReceiverSession error: %v", e)
	}

	srv.mu.RLock()
	active := srv.ActiveRecvSession
	localState := srv.LocalReceiverState
	history := make([]*ReceiverSession, 0, len(srv.SessionHistory))
	for _, hs := range srv.SessionHistory {
		history = append(history, hs)
	}
	srv.mu.RUnlock()

	if active == nil || localState != RecvReady {
		t.Fatalf("expected active session in READY_TO_RECEIVE, got active=%v, state=%s", active, localState)
	}

	readyCount := 0
	completedCount := 0
	for _, hs := range history {
		st := hs.GetState()
		switch st {
		case RecvReady:
			readyCount++
			if hs.SessionID != active.SessionID {
				t.Fatalf("non-active session %s still in RecvReady", hs.SessionID)
			}
		case RecvCompleted:
			completedCount++
			select {
			case <-hs.DoneChan:
			default:
				t.Fatalf("completed session %s did not close DoneChan", hs.SessionID)
			}
		default:
			t.Fatalf("unexpected session %s state: %s", hs.SessionID, st)
		}
	}

	if readyCount != 1 || completedCount != workers-1 {
		t.Fatalf("expected 1 ready and %d completed sessions, got ready=%d, completed=%d", workers-1, readyCount, completedCount)
	}
}

// 14. Regression Test (Case C): Cancelling a receiver session during listener startup
func TestRegression_CancelDuringStartup(t *testing.T) {
	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	binder := &ControlledStartupBinder{
		bindEntered: make(chan struct{}),
		bindRelease: make(chan struct{}),
	}
	srv.Binder = binder

	udpPort := findFreeUDPPort(t)
	req := PeerPrepareRequest{
		SessionID:        randomHex(16),
		Nonce:            randomHex(16),
		ExpectedSourceIP: "127.0.0.1",
		TestType:         "udp",
		UDPPort:          udpPort,
		MaxPackets:       3,
		TimeoutSec:       30,
	}

	type startResult struct {
		resp *PeerPrepareResponse
		err  error
	}
	resCh := make(chan startResult, 1)

	go func() {
		r, sErr := srv.StartReceiverSession(req, srv.PairingSecret)
		resCh <- startResult{resp: r, err: sErr}
	}()

	select {
	case <-binder.bindEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for listener startup to enter ListenUDP")
	}

	srv.mu.RLock()
	midState := srv.LocalReceiverState
	initializingSess := srv.ActiveRecvSession
	srv.mu.RUnlock()

	if midState != RecvInitializing || initializingSess == nil {
		t.Fatalf("expected RECEIVER_INITIALIZING during startup, got state=%s, sess=%v", midState, initializingSess)
	}

	cancelDone := make(chan bool, 1)
	go func() {
		cancelDone <- srv.CancelReceiverSession(req.SessionID)
	}()

	for !initializingSess.IsCancelled() {
		time.Sleep(1 * time.Millisecond)
	}
	close(binder.bindRelease)

	select {
	case sr := <-resCh:
		if sr.err == nil {
			t.Fatalf("expected error when session is cancelled during startup, but got READY_TO_RECEIVE: %+v", sr.resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK DETECTED when cancelling session during startup")
	}

	select {
	case ok := <-cancelDone:
		if !ok {
			t.Fatal("expected CancelReceiverSession to return true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CancelReceiverSession hung waiting for startup cancellation")
	}

	if closed := atomic.LoadInt32(&binder.closedCount); closed != 1 {
		t.Fatalf("expected partially bound UDP socket to be closed once, got closedCount=%d", closed)
	}

	srv.mu.RLock()
	finalState := srv.LocalReceiverState
	activeAfter := srv.ActiveRecvSession
	srv.mu.RUnlock()

	if finalState != RecvIdle || activeAfter != nil {
		t.Fatalf("expected state IDLE and nil ActiveRecvSession after cancelled startup, got state=%s, active=%v", finalState, activeAfter)
	}
}

// 15. Regression Test (Case D): Repeated concurrent cancellation during shutdown is idempotent
func TestRegression_RepeatedCancellationDuringShutdown(t *testing.T) {
	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	udpPort := findFreeUDPPort(t)
	req := PeerPrepareRequest{
		SessionID:        randomHex(16),
		Nonce:            randomHex(16),
		ExpectedSourceIP: "127.0.0.1",
		TestType:         "udp",
		UDPPort:          udpPort,
		MaxPackets:       3,
		TimeoutSec:       30,
	}

	if _, err := srv.StartReceiverSession(req, srv.PairingSecret); err != nil {
		t.Fatalf("StartReceiverSession failed: %v", err)
	}

	srv.mu.RLock()
	sess := srv.ActiveRecvSession
	srv.mu.RUnlock()

	const cancelCallers = 20
	barrier := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < cancelCallers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier
			switch idx % 3 {
			case 0:
				sess.Cancel()
				<-sess.DoneChan
			case 1:
				srv.CancelReceiverSession(req.SessionID)
			default:
				srv.StopActiveReceiverSession()
			}
		}(i)
	}
	close(barrier)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK DETECTED during repeated concurrent session cancellation")
	}

	srv.mu.RLock()
	finalState := srv.LocalReceiverState
	srv.mu.RUnlock()
	if finalState != RecvIdle {
		t.Fatalf("expected server state IDLE after shutdown, got %s", finalState)
	}
}

// 16. Regression Test (Case E): Old session cleanup cannot overwrite newer session's state
func TestRegression_OldSessionCleanupCannotOverwriteNewSessionState(t *testing.T) {
	srv, err := NewAppServer(&MockCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	udpPort := findFreeUDPPort(t)
	req1 := PeerPrepareRequest{
		SessionID:        randomHex(16),
		Nonce:            randomHex(16),
		ExpectedSourceIP: "127.0.0.1",
		TestType:         "udp",
		UDPPort:          udpPort,
		MaxPackets:       3,
		TimeoutSec:       30,
	}
	if _, err := srv.StartReceiverSession(req1, srv.PairingSecret); err != nil {
		t.Fatal(err)
	}
	srv.mu.RLock()
	sess1 := srv.ActiveRecvSession
	srv.mu.RUnlock()

	req2 := PeerPrepareRequest{
		SessionID:        randomHex(16),
		Nonce:            randomHex(16),
		ExpectedSourceIP: "127.0.0.1",
		TestType:         "udp",
		UDPPort:          udpPort,
		MaxPackets:       3,
		TimeoutSec:       30,
	}
	if _, err := srv.StartReceiverSession(req2, srv.PairingSecret); err != nil {
		t.Fatal(err)
	}
	srv.mu.RLock()
	sess2 := srv.ActiveRecvSession
	srv.mu.RUnlock()

	if sess1.Generation >= sess2.Generation {
		t.Fatalf("expected monotonic generation increase: sess1=%d, sess2=%d", sess1.Generation, sess2.Generation)
	}

	srv.onSessionExit(sess1, RecvIdle)
	srv.onSessionExit(sess1, RecvError)
	sess1.Cancel()

	srv.mu.RLock()
	currentState := srv.LocalReceiverState
	currentActive := srv.ActiveRecvSession
	srv.mu.RUnlock()

	if currentState != RecvReady {
		t.Fatalf("old session cleanup overwrote newer session state: expected READY_TO_RECEIVE, got %s", currentState)
	}
	if currentActive != sess2 {
		t.Fatalf("old session cleanup overwrote ActiveRecvSession pointer")
	}
}
