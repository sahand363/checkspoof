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
	"sync/atomic"
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

// findFreeUDPPort reserves and releases an available local UDP port for deterministic tests.
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

// trackedPacketConn wraps net.PacketConn to count Close() invocations deterministically.
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

// ControlledStartupBinder coordinates listener binding via channels (zero sleeps)
// to test cancellation during startup and concurrent preparation deterministically.
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

	if testRes.PrimaryClassification != ClassRemoteVerified {
		t.Fatalf("expected REMOTE_PACKET_VERIFIED, got %s (%s)", testRes.PrimaryClassification, testRes.ConfirmedEvidence)
	}
	if testRes.PacketsSent != 3 || testRes.RemoteVerifiedCount != 3 {
		t.Fatalf("expected 3 sent and 3 verified packets, got sent=%d, verified=%d", testRes.PacketsSent, testRes.RemoteVerifiedCount)
	}
}

// 5. Regression Test (Case A): Replacing an active receiver session must not deadlock
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

	// Repeatedly replace the active session on the exact same UDP port with a strict timeout
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

	// Verify sess1 was cleanly stopped and closed
	select {
	case <-sess1.DoneChan:
	default:
		t.Fatal("expected sess1.DoneChan to be closed after replacement")
	}
	if st := sess1.GetState(); st != RecvCompleted {
		t.Fatalf("expected sess1 state RecvCompleted, got %s", st)
	}

	// Verify the latest session is active and server state is READY_TO_RECEIVE
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

// 6. Regression Test (Case B): Concurrent StartReceiverSession calls must serialize cleanly
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

	// Verify deterministic final state: exactly 1 session is active and READY_TO_RECEIVE,
	// and all other (workers - 1) sessions in SessionHistory are stopped.
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

// 7. Regression Test (Case C): Cancelling a receiver session during listener startup
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

	// Deterministically wait until ListenUDP is in progress
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

	// Cancel the session while initialization is still paused inside ListenUDP
	cancelDone := make(chan bool, 1)
	go func() {
		cancelDone <- srv.CancelReceiverSession(req.SessionID)
	}()

	// Wait until sess.IsCancelled() is observed, then release ListenUDP
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

	// Verify partial socket resource was closed and server state is IDLE (not READY_TO_RECEIVE)
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

// 8. Regression Test (Case D): Repeated concurrent cancellation during shutdown is idempotent
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

// 9. Regression Test (Case E): Old session cleanup cannot overwrite newer session's state
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

	// Simulate late/out-of-order cleanup callbacks from the old session (sess1)
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
