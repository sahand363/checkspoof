package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type MockCommandCall struct {
	Name string
	Args []string
}

type MockCommandRunner struct {
	mu          sync.Mutex
	Calls       []MockCommandCall
	LastSpoofIP string
	RouteFail   bool
	PermFail    bool
}

func (m *MockCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, MockCommandCall{Name: name, Args: args})

	for i, arg := range args {
		if arg == "--to-source" && i+1 < len(args) {
			m.LastSpoofIP = args[i+1]
		}
	}

	cmdLine := name + " " + strings.Join(args, " ")
	if name == "ip" && strings.Contains(cmdLine, "route get") {
		if m.RouteFail {
			return []byte("RTNETLINK answers: Network is unreachable"), 2, nil
		}
		return []byte("127.0.0.1 via 10.0.0.1 dev eth0 src 10.0.0.15 uid 0"), 0, nil
	}

	if name == "iptables" {
		if m.PermFail {
			return []byte("iptables: Permission denied (you must be root)."), 4, context.DeadlineExceeded
		}
		if strings.Contains(cmdLine, "-L CSPF_") {
			spoof := m.LastSpoofIP
			if spoof == "" {
				spoof = "8.8.8.8"
			}
			out := fmt.Sprintf("Chain CSPF_TEST (1 references)\n"+
				"    pkts      bytes target     prot opt in     out     source               destination\n"+
				"       3      252 SNAT       all  --  *      eth0    0.0.0.0/0            127.0.0.1            to:%s\n", spoof)
			return []byte(out), 0, nil
		}
		return []byte(""), 0, nil
	}

	if name == "ping" {
		return []byte("1 packets transmitted, 0 received, 100% packet loss"), 1, nil
	}

	return []byte(""), 0, nil
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

	// Tamper with sequence number
	tampered := bytes.Replace(validPayload, []byte("|udp|2|"), []byte("|udp|3|"), 1)
	if _, err := ValidateUDPPacketPayload(tampered, secret, sessionID, nonce, 5); err == nil {
		t.Fatal("expected HMAC failure on tampered sequence number")
	}

	// Wrong session ID
	if _, err := ValidateUDPPacketPayload(validPayload, secret, randomHex(16), nonce, 5); err == nil {
		t.Fatal("expected session ID mismatch error")
	}

	// Expired timestamp (replay attack)
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

	// Construct realistic ICMP Echo Request (Type=8, Code=0, ID=0x1234, Seq=1, 16B timestamp + repeated pattern)
	icmpPkt := make([]byte, 8+16+32)
	icmpPkt[0] = 8 // Echo Request
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

	// Reject ICMP Echo Reply (Type=0)
	icmpPkt[0] = 0
	if _, _, _, err := ValidateICMPRawPacket(icmpPkt, secret, sessionID, nonce, 5); err == nil {
		t.Fatal("expected rejection for ICMP Echo Reply (Type 0)")
	}
}

// 3. Test Isolated SNAT Chain Creation, Counter Parsing & Guaranteed Cleanup
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
	if iso.ChainName != "CSPF_A1B2C3D4" {
		t.Fatalf("expected chain name CSPF_A1B2C3D4, got %s", iso.ChainName)
	}

	pkts, bCount, _, err := iso.ReadCounters(ctx)
	if err != nil || pkts != 3 || bCount != 252 {
		t.Fatalf("expected pkts=3, bytes=252, got pkts=%d, bytes=%d, err=%v", pkts, bCount, err)
	}

	iso.Cleanup()

	// Verify cleanup commands (-D POSTROUTING, -F CSPF_A1B2C3D4, -X CSPF_A1B2C3D4) were executed
	var sawDeleteJump, sawFlush, sawDeleteChain bool
	for _, c := range mockRunner.Calls {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "-D POSTROUTING") && strings.Contains(joined, "CSPF_A1B2C3D4") {
			sawDeleteJump = true
		}
		if strings.Contains(joined, "-F CSPF_A1B2C3D4") {
			sawFlush = true
		}
		if strings.Contains(joined, "-X CSPF_A1B2C3D4") {
			sawDeleteChain = true
		}
	}
	if !sawDeleteJump || !sawFlush || !sawDeleteChain {
		t.Fatalf("incomplete cleanup: deleteJump=%v, flush=%v, deleteChain=%v", sawDeleteJump, sawFlush, sawDeleteChain)
	}
}

// 4. Test Two-Server TLS 1.3 Pairing, Receiver Readiness Handshake, and End-to-End UDP Verification
func TestEndToEndTwoServerReadinessAndUDPVerification(t *testing.T) {
	runnerA := &MockCommandRunner{}
	runnerB := &MockCommandRunner{}

	srvA, err := NewAppServer(runnerA)
	if err != nil {
		t.Fatal(err)
	}
	srvB, err := NewAppServer(runnerB)
	if err != nil {
		t.Fatal(err)
	}

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

	// Step 1: Attempt test before pairing/preparing -> must fail with 412 Precondition Failed
	reqTestEarly, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/test", strings.NewReader(`{}`))
	reqTestEarly.Header.Set("X-Admin-Key", srvA.AdminKey)
	respEarly, err := http.DefaultClient.Do(reqTestEarly)
	if err != nil || respEarly.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 Precondition Failed before readiness, got %v", respEarly)
	}
	_ = respEarly.Body.Close()

	// Step 2: Pair Server A with Server B using Server B's pairing token over TLS 1.3
	tokenB := srvB.PairingToken()
	pairBody, _ := json.Marshal(map[string]string{"remote_token": tokenB})
	reqPair, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portA+"/api/admin/pair", bytes.NewReader(pairBody))
	reqPair.Header.Set("X-Admin-Key", srvA.AdminKey)
	respPair, err := http.DefaultClient.Do(reqPair)
	if err != nil || respPair.StatusCode != http.StatusOK {
		t.Fatalf("pairing failed: err=%v, status=%v", err, respPair)
	}
	_ = respPair.Body.Close()

	// Verify pairing did NOT start receiver listener prematurely
	srvB.mu.RLock()
	initialRecvState := srvB.LocalReceiverState
	srvB.mu.RUnlock()
	if initialRecvState != RecvIdle {
		t.Fatalf("expected Server B receiver state to remain IDLE after pairing, got %s", initialRecvState)
	}

	// Step 3: Prepare Receiver on Server B (expecting loopback source 127.0.0.1 for local test)
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

	// Verify Server B is now genuinely READY_TO_RECEIVE and holding the UDP listener open
	srvB.mu.RLock()
	bState := srvB.LocalReceiverState
	srvB.mu.RUnlock()
	if bState != RecvReady {
		t.Fatalf("expected Server B state READY_TO_RECEIVE, got %s", bState)
	}

	// Step 4: Execute the coordinated UDP test
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

	if testRes.PrimaryClassification != ClassRemoteVerified {
		t.Fatalf("expected REMOTE_PACKET_VERIFIED, got %s (%s)", testRes.PrimaryClassification, testRes.ConfirmedEvidence)
	}
	if testRes.PacketsSent != 3 || testRes.RemoteVerifiedCount != 3 {
		t.Fatalf("expected 3 sent and 3 verified packets, got sent=%d, verified=%d", testRes.PacketsSent, testRes.RemoteVerifiedCount)
	}
}
