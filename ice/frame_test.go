package ice

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestTransportIdentityMatches(t *testing.T) {
	header := http.Header{"Authorization": []string{`GoNZBNet node_id="node_a",timestamp="now",nonce="nonce",signature="signature"`}}
	if err := transportIdentityMatches("node_a", header); err != nil {
		t.Fatal(err)
	}
	if err := transportIdentityMatches("node_b", header); err == nil {
		t.Fatal("mismatched transport identity accepted")
	}
	duplicate := header.Clone()
	duplicate.Set("Authorization", `GoNZBNet node_id="node_a",timestamp="now",nonce="nonce",signature="signature",node_id="node_b"`)
	if err := transportIdentityMatches("node_a", duplicate); err == nil {
		t.Fatal("duplicate transport identity accepted")
	}
	multiple := header.Clone()
	multiple["Authorization"] = append(multiple["Authorization"], multiple.Get("Authorization"))
	if err := transportIdentityMatches("node_a", multiple); err == nil {
		t.Fatal("multiple authorization headers accepted")
	}
}

func TestReceiveMessageEnforcesSharedBodyBudget(t *testing.T) {
	frames := make(chan []byte, 3)
	frames <- []byte{frameHeader, '{', '}'}
	frames <- []byte{frameData, '1', '2', '3', '4', '5'}
	frames <- []byte{frameEnd}
	close(frames)
	budget := &byteBudget{limit: 4}
	if _, _, err := receiveMessageWithBudget(context.Background(), frames, &requestHeader{}, 1024, budget); err == nil {
		t.Fatal("body larger than the shared budget was accepted")
	}
	if used := budget.used.Load(); used != 0 {
		t.Fatalf("failed receive leaked %d budget bytes", used)
	}
}

func TestPeerChannelRateIsBounded(t *testing.T) {
	item := &peer{}
	now := time.Now().UTC()
	if !item.allowChannel(now, 2) {
		t.Fatal("channel rate rejected the first channel")
	}
	if !item.allowChannel(now, 2) {
		t.Fatal("channel rate rejected traffic before its boundary")
	}
	if item.allowChannel(now, 2) {
		t.Fatal("channel rate exceeded its boundary")
	}
	if !item.allowChannel(now.Add(time.Minute), 2) {
		t.Fatal("channel rate did not reset")
	}
	if !item.allowRequest(now, 1) {
		t.Fatal("first request was rate limited")
	}
	if item.allowRequest(now, 1) {
		t.Fatal("request rate boundary was not enforced")
	}
}

func TestBoundedRecorderRejectsOversize(t *testing.T) {
	recorder := newBoundedRecorder(4)
	if _, err := recorder.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Write([]byte("5")); err == nil {
		t.Fatal("oversize response accepted")
	}
}

func TestResponseMemoryRemainsChargedUntilConsumed(t *testing.T) {
	budget := &byteBudget{limit: 4}
	if !budget.reserve(4) {
		t.Fatal("failed to reserve response body")
	}
	body := newBudgetedReadCloser([]byte("1234"), budget)
	if budget.used.Load() != 4 {
		t.Fatal("response body was not charged to the budget")
	}
	if _, err := io.Copy(io.Discard, body); err != nil {
		t.Fatal(err)
	}
	if budget.used.Load() != 0 {
		t.Fatal("consumed response body did not release its budget")
	}

	requestBudget := &byteBudget{limit: 4}
	if _, err := readLimitedWithBudget(bytes.NewBufferString("12345"), 8, requestBudget); err == nil {
		t.Fatal("request exceeding the shared budget was accepted")
	}
	if requestBudget.used.Load() != 0 {
		t.Fatal("failed request body leaked its budget")
	}
}

func TestTransportBodyIdentityMatches(t *testing.T) {
	if err := transportBodyIdentityMatches("node_a", []byte(`{"author_node_id":"node_a"}`)); err != nil {
		t.Fatal(err)
	}
	if err := transportBodyIdentityMatches("node_a", []byte(`{"author_node_id":"node_b"}`)); err == nil {
		t.Fatal("mismatched signed body identity accepted")
	}
}

func TestTraversalPathIsolation(t *testing.T) {
	manager := &Manager{cfg: Config{AllowedBasePath: "/gonzbnet/v1"}}
	for _, path := range []string{"/.well-known/gonzbnet", "/gonzbnet/v1", "/gonzbnet/v1/events", "/gonzbnet/v1/gossip"} {
		if !manager.pathAllowed(path) {
			t.Fatalf("expected %q to be allowed", path)
		}
	}
	for _, path := range []string{"/setup", "/api", "/api/v1/admin", "/gonzbnet/v10", "/gonzbnet/v1/../api", "/gonzbnet/v1\\admin", "/", "https://example.invalid/gonzbnet/v1"} {
		if manager.pathAllowed(path) {
			t.Fatalf("unexpected traversal access to %q", path)
		}
	}
	if manager.pathAllowed("/gonzbnet/v1/%2e%2e/api") {
		t.Fatal("percent-encoded traversal path was accepted")
	}
}

func TestValidateHTTPHeaderRejectsAmbiguousAndHopByHopFields(t *testing.T) {
	for name, header := range map[string]http.Header{
		"noncanonical": {"authorization": []string{"value"}},
		"hop by hop":   {"Connection": []string{"keep-alive"}},
		"newline":      {"X-Test": []string{"value\r\ninjected: true"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateHTTPHeader(header); err == nil {
				t.Fatal("unsafe traversal header was accepted")
			}
		})
	}
}

func TestReceiveMessageRejectsMalformedFrames(t *testing.T) {
	tests := []struct {
		name   string
		frames [][]byte
	}{
		{name: "missing header", frames: [][]byte{{frameData, 'x'}}},
		{name: "empty frame", frames: [][]byte{{frameHeader, '{', '}'}, {}}},
		{name: "duplicate header", frames: [][]byte{{frameHeader, '{', '}'}, {frameHeader, '{', '}'}}},
		{name: "end payload", frames: [][]byte{{frameHeader, '{', '}'}, {frameEnd, 'x'}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			messages := make(chan []byte, len(test.frames))
			for _, frame := range test.frames {
				messages <- frame
			}
			close(messages)
			if _, _, err := receiveMessage(context.Background(), messages, &requestHeader{}, 1024); err == nil {
				t.Fatal("malformed frame sequence accepted")
			}
		})
	}
}

func FuzzReceiveMessageFrames(f *testing.F) {
	f.Add([]byte{frameHeader, '{', '}'}, []byte{frameEnd})
	f.Add([]byte{frameData, 'x'}, []byte{})
	f.Fuzz(func(t *testing.T, first, second []byte) {
		if len(first) > maxHeaderBytes+1 || len(second) > maxHeaderBytes+1 {
			return
		}
		messages := make(chan []byte, 3)
		messages <- append([]byte(nil), first...)
		messages <- append([]byte(nil), second...)
		messages <- []byte{frameEnd}
		close(messages)
		body, _, err := receiveMessage(context.Background(), messages, &requestHeader{}, 1<<20)
		if err == nil && len(body) > 1<<20 {
			t.Fatal("fuzzed receive exceeded its body bound")
		}
	})
}

func TestInitialOfferNegotiatesSCTPDataChannels(t *testing.T) {
	manager := &Manager{
		cfg:      Config{GatherTimeout: time.Second, ConnectTimeout: time.Second, MaxBodyBytes: 1024},
		ctx:      context.Background(),
		peers:    make(map[string]*peer),
		sessions: make(map[string]*peer),
	}
	state := &coordinatorState{}
	item := &peer{manager: manager, nodeID: "peer", coordinator: state, connected: make(chan struct{}), done: make(chan struct{})}
	pc, err := manager.newPeerConnection(item, "session")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.CreateDataChannel("control/1", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(offer.SDP, "m=application") || !strings.Contains(offer.SDP, "webrtc-datachannel") {
		t.Fatalf("initial offer did not negotiate SCTP DataChannels:\n%s", offer.SDP)
	}
}

func TestValidateRemoteSDPEnforcesDataChannelSecurityProfile(t *testing.T) {
	api := newWebRTCAPI(nil, nil)
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.CreateDataChannel("control/1", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-complete:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate gathering timed out")
	}
	sdp := pc.LocalDescription().SDP
	if err := validateRemoteSDP(sdp); err != nil {
		t.Fatalf("valid Pion DataChannel SDP rejected: %v\n%s", err, sdp)
	}
	tests := map[string]string{
		"weak fingerprint":      strings.Replace(sdp, "fingerprint:sha-256", "fingerprint:sha-1", 1),
		"second media":          sdp + "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
		"loopback target":       sdp + "a=candidate:blocked 1 udp 1 127.0.0.1 9999 typ host\r\n",
		"duplicate fingerprint": sdp + "a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n",
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateRemoteSDP(candidate); err == nil {
				t.Fatal("unsafe remote SDP was accepted")
			}
		})
	}
	overflow := sdp
	for index := 0; index < maxRemoteCandidates+1; index++ {
		overflow += fmt.Sprintf("a=candidate:extra%d 1 udp 1 192.168.10.%d 9999 typ host\r\n", index, index+1)
	}
	if err := validateRemoteSDP(overflow); err == nil {
		t.Fatal("remote SDP candidate flood was accepted")
	}
}

func TestWaitForGatheringRejectsPartialNonTrickleSDP(t *testing.T) {
	complete := make(chan struct{})
	if err := waitForGathering(context.Background(), complete, time.Millisecond); err == nil {
		t.Fatal("incomplete candidate gathering was accepted")
	}
}

func TestChannelAdmissionWaitsForBoundedTurnover(t *testing.T) {
	item := &peer{}
	item.channels.Store(maxInboundChannels)
	go func() {
		time.Sleep(10 * time.Millisecond)
		item.channels.Add(-1)
	}()
	if !item.acquireChannel(context.Background(), maxInboundChannels, 100*time.Millisecond) {
		t.Fatal("channel turnover was rejected")
	}
	if got := item.channels.Load(); got != maxInboundChannels {
		t.Fatalf("channel count after turnover = %d", got)
	}
	if item.acquireChannel(context.Background(), maxInboundChannels, 5*time.Millisecond) {
		t.Fatal("channel admission exceeded its bound")
	}
}
