package coordinator

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/datallboy/gonzb-connect/protocol"
)

func TestEnrollmentTokenHashAndParsing(t *testing.T) {
	hash, err := hashToken("secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyToken("secret-value", hash) || verifyToken("other-value", hash) {
		t.Fatal("Argon2id verification failed")
	}
	wantID := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	wantSecret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	id, secret, err := parseToken("gzc_" + wantID + "." + wantSecret)
	if err != nil || id != wantID || secret != wantSecret {
		t.Fatalf("parse = %q %q %v", id, secret, err)
	}
	for _, invalid := range []string{"Bearer gzc_" + wantID + "." + wantSecret, "gzc_short.short", " gzc_" + wantID + "." + wantSecret, "gzc_" + wantID + "." + wantSecret + ".extra"} {
		if _, _, err := parseToken(invalid); err == nil {
			t.Fatalf("invalid enrollment token %q was accepted", invalid)
		}
	}
}

func TestCoordinatorQuotas(t *testing.T) {
	server := NewServer(nil, Config{MaxRegistrationsPerNode: 2, MaxNegotiationsPerNode: 8, NegotiationsPerMinute: 30})
	first := &registration{nodeID: "node_a"}
	second := &registration{nodeID: "node_a"}
	third := &registration{nodeID: "node_a"}
	if !server.addRegistration(first) || !server.addRegistration(second) || server.addRegistration(third) {
		t.Fatal("registration quota was not enforced")
	}
	for index := 0; index < 8; index++ {
		envelope := protocol.Envelope{MessageType: protocol.MessageOffer, SessionID: fmt.Sprintf("session-%d", index), SourceNodeID: "node_a", TargetNodeID: "node_b"}
		if !server.trackNegotiation(envelope) {
			t.Fatalf("negotiation %d rejected before quota", index)
		}
	}
	if server.trackNegotiation(protocol.Envelope{MessageType: protocol.MessageOffer, SessionID: "session-over", SourceNodeID: "node_a", TargetNodeID: "node_b"}) {
		t.Fatal("negotiation quota was not enforced")
	}
	if server.trackNegotiation(protocol.Envelope{MessageType: protocol.MessageOffer, SessionID: "target-over", SourceNodeID: "node_c", TargetNodeID: "node_b"}) {
		t.Fatal("target negotiation quota was not enforced")
	}
	connectServer := NewServer(nil, Config{MaxNegotiationsPerNode: 1})
	connect := protocol.Envelope{MessageType: protocol.MessageConnect, SessionID: "connect", SourceNodeID: "node_b", TargetNodeID: "node_a"}
	if !connectServer.trackNegotiation(connect) {
		t.Fatal("initial connect notification was rejected")
	}
	if !connectServer.trackNegotiation(connect) || len(connectServer.sessions) != 0 {
		t.Fatal("connect notifications should not consume active negotiation sessions")
	}
	server.rates["node_rate"] = rateWindow{started: time.Now().UTC()}
	for index := 0; index < 30; index++ {
		if !server.allowNegotiationRate("node_rate") {
			t.Fatalf("rate item %d rejected before quota", index)
		}
	}
	if server.allowNegotiationRate("node_rate") {
		t.Fatal("negotiation rate quota was not enforced")
	}
}
