package ice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/datallboy/gonzb-connect/protocol"
	"github.com/pion/webrtc/v4"
)

func TestTwoPeerManagersExchangeConcurrentHTTPAndPersistentGossip(t *testing.T) {
	nodeA := randomNodeID(t)
	nodeB := randomNodeID(t)
	stateA := &coordinatorState{config: CoordinatorConfig{URL: "https://connect.example"}}
	stateB := &coordinatorState{config: CoordinatorConfig{URL: "https://connect.example"}}
	managerA := integrationManager(nodeA, nodeB, stateA)
	managerB := integrationManager(nodeB, nodeA, stateB)
	managerB.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get(TransportNodeIDHeader) != nodeA {
			t.Errorf("transport node ID = %q", request.Header.Get(TransportNodeIDHeader))
			http.Error(w, "identity mismatch", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))

	peerA := managerA.peers[nodeB]
	peerB := managerB.peers[nodeA]
	pcA, err := managerA.newPeerConnection(peerA, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	defer pcA.Close()
	pcB, err := managerB.newPeerConnection(peerB, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	defer pcB.Close()
	control, err := pcA.CreateDataChannel("control/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	control.OnOpen(func() { _ = control.Close() })
	negotiatePeerConnections(t, pcA, pcB)
	waitConnected(t, peerA)
	waitConnected(t, peerB)

	const requests = 8
	errors := make(chan error, requests)
	var wait sync.WaitGroup
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := managerA.RoundTrip(newTraversalRequest(t, nodeB, "/gonzbnet/v1/echo", []byte("ordinary")))
			if err != nil {
				errors <- err
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(body, []byte("ordinary")) {
				errors <- &integrationError{"ordinary response mismatch", err}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	// This exceeds both the DataChannel high-water mark and the bounded
	// inbound message queue. It regresses sender flow control for manifest-
	// sized streams without weakening receiver memory bounds.
	largePayload := bytes.Repeat([]byte("large-frame-flow-control"), 24<<10)
	response, err := managerA.RoundTrip(newTraversalRequest(t, nodeB, "/gonzbnet/v1/echo", largePayload))
	if err != nil {
		t.Fatal(err)
	}
	largeResponse, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || !bytes.Equal(largeResponse, largePayload) {
		t.Fatalf("large response mismatch: bytes=%d err=%v", len(largeResponse), readErr)
	}

	stateA.mu.Lock()
	stateA.connected = false // An established PeerConnection must not need signaling.
	stateA.mu.Unlock()
	for _, payload := range [][]byte{[]byte("gossip-one"), []byte("gossip-two")} {
		response, err := managerA.RoundTrip(newTraversalRequest(t, nodeB, "/gonzbnet/v1/gossip", payload))
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || !bytes.Equal(body, payload) {
			t.Fatalf("gossip response = %q, %v", body, readErr)
		}
	}
	peerA.gossipMu.Lock()
	gossip := peerA.gossip
	peerA.gossipMu.Unlock()
	if gossip == nil || gossip.channel == nil || gossip.channel.ReadyState() != webrtc.DataChannelStateOpen {
		t.Fatal("persistent gossip channel was not reused")
	}
	status := managerA.Status()
	if status.NodeID != nodeA || len(status.Peers) != 1 {
		t.Fatalf("unexpected manager status: %+v", status)
	}
	if status.Peers[0].PathType != "direct" || status.Peers[0].BytesSent == 0 || status.Peers[0].BytesReceived == 0 {
		t.Fatalf("transport status omits path or byte counters: %+v", status.Peers[0])
	}
	if status.InflightBodyBytes != 0 {
		t.Fatalf("in-flight body bytes did not return to zero: %d", status.InflightBodyBytes)
	}
}

type integrationError struct {
	message string
	err     error
}

func (e *integrationError) Error() string {
	if e.err != nil {
		return e.message + ": " + e.err.Error()
	}
	return e.message
}

func integrationManager(localNodeID, peerNodeID string, state *coordinatorState) *Manager {
	ctx := context.Background()
	manager := &Manager{
		cfg: Config{
			ConnectTimeout: 5 * time.Second, RequestTimeout: 5 * time.Second, MaxBodyBytes: 1 << 20,
			MaxPeerConnections: 32, AllowedBasePath: "/gonzbnet/v1", ChannelsPerMinute: 120, RequestsPerMinute: 240,
		},
		nodeID: localNodeID, api: newWebRTCAPI(nil, nil), ctx: ctx, started: true,
		coordinators: map[string]*coordinatorState{"connect.example": state},
		peers:        make(map[string]*peer), sessions: make(map[string]*peer), replay: protocol.NewReplayCache(),
		inboundSem: make(chan struct{}, 64), bodyBudget: &byteBudget{limit: 8 << 20},
	}
	manager.peers[peerNodeID] = &peer{
		manager: manager, nodeID: peerNodeID, coordinator: state,
		connected: make(chan struct{}), done: make(chan struct{}), lastUsed: time.Now().UTC(),
	}
	return manager
}

func negotiatePeerConnections(t *testing.T, offerer, answerer *webrtc.PeerConnection) {
	t.Helper()
	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	offerComplete := webrtc.GatheringCompletePromise(offerer)
	if err := offerer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	waitGatherComplete(t, offerComplete)
	if err := validateRemoteSDP(offerer.LocalDescription().SDP); err != nil {
		t.Fatal(err)
	}
	if err := answerer.SetRemoteDescription(*offerer.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	answerComplete := webrtc.GatheringCompletePromise(answerer)
	if err := answerer.SetLocalDescription(answer); err != nil {
		t.Fatal(err)
	}
	waitGatherComplete(t, answerComplete)
	if err := validateRemoteSDP(answerer.LocalDescription().SDP); err != nil {
		t.Fatal(err)
	}
	if err := offerer.SetRemoteDescription(*answerer.LocalDescription()); err != nil {
		t.Fatal(err)
	}
}

func waitGatherComplete(t *testing.T, complete <-chan struct{}) {
	t.Helper()
	select {
	case <-complete:
	case <-time.After(5 * time.Second):
		t.Fatal("ICE candidate gathering timed out")
	}
}

func waitConnected(t *testing.T, item *peer) {
	t.Helper()
	select {
	case <-item.connected:
	case <-item.done:
		t.Fatal("PeerConnection closed before connecting")
	case <-time.After(5 * time.Second):
		t.Fatal("PeerConnection did not connect")
	}
}

func newTraversalRequest(t *testing.T, targetNodeID, path string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, Scheme+"://"+targetNodeID+"@connect.example"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func randomNodeID(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NodeIDFromPublicKey(publicKey)
}
