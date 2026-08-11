package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

type testSigner struct{ private ed25519.PrivateKey }

func (s testSigner) NodeID(context.Context) (string, error) {
	return NodeIDFromPublicKey(s.private.Public().(ed25519.PublicKey)), nil
}
func (s testSigner) PublicKey(context.Context) (ed25519.PublicKey, error) {
	return s.private.Public().(ed25519.PublicKey), nil
}
func (s testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

func TestEnvelopeBindsExactPayloadAndFingerprint(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := testSigner{private: privateKey}
	now := time.Now().UTC()
	target := "node_" + strings.Repeat("a", 52)
	envelope, err := NewEnvelope(t.Context(), signer, MessageOffer, "session-a", target, "v=0\r\na=fingerprint:sha-256 AA\r\n", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Verify(now, time.Minute); err != nil {
		t.Fatalf("verify envelope: %v", err)
	}
	envelope.Payload = strings.Replace(envelope.Payload, "AA", "BB", 1)
	if _, err := envelope.Verify(now, time.Minute); err == nil {
		t.Fatal("altered SDP fingerprint should fail")
	}
}

func TestEnvelopeRejectsCoordinatorSubstitution(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	target := "node_" + strings.Repeat("a", 52)
	alternateKey, _, _ := ed25519.GenerateKey(rand.Reader)
	alternateTarget := NodeIDFromPublicKey(alternateKey)
	envelope, err := NewEnvelope(t.Context(), testSigner{private: privateKey}, MessageOffer, "session-a", target, "v=0\r\n", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Envelope){
		"destination":  func(item *Envelope) { item.TargetNodeID = alternateTarget },
		"message type": func(item *Envelope) { item.MessageType = MessageAnswer },
		"session":      func(item *Envelope) { item.SessionID = "swapped-session" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := envelope
			mutate(&tampered)
			if _, err := tampered.Verify(now, time.Minute); err == nil {
				t.Fatal("substituted signaling envelope verified")
			}
		})
	}
}

func TestEnvelopeRejectsInvalidMessageShape(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := testSigner{private: privateKey}
	target := "node_" + strings.Repeat("a", 52)
	if _, err := NewEnvelope(t.Context(), signer, MessageConnect, "session-a", target, "unexpected", time.Now().UTC(), time.Minute); err == nil {
		t.Fatal("connect payload was accepted")
	}
	if _, err := NewEnvelope(t.Context(), signer, MessageOffer, "session with spaces", target, "v=0\r\n", time.Now().UTC(), time.Minute); err == nil {
		t.Fatal("invalid session identifier was accepted")
	}
}

func TestReplayCacheRejectsSecondUse(t *testing.T) {
	now := time.Now().UTC()
	cache := NewReplayCache()
	if !cache.Consume("node_a", "nonce", now.Add(time.Minute), now) {
		t.Fatal("first replay-cache use failed")
	}
	if cache.Consume("node_a", "nonce", now.Add(time.Minute), now) {
		t.Fatal("replay was accepted")
	}
}

func TestReplayCacheIsBoundedAndReclaimsExpiredEntries(t *testing.T) {
	now := time.Now().UTC()
	cache := NewReplayCacheWithLimit(2)
	if !cache.Consume("node_a", "one", now.Add(time.Second), now) ||
		!cache.Consume("node_a", "two", now.Add(time.Minute), now) {
		t.Fatal("cache rejected entries before reaching its limit")
	}
	if cache.Consume("node_a", "three", now.Add(time.Minute), now) {
		t.Fatal("cache accepted an entry beyond its limit")
	}
	if !cache.Consume("node_a", "three", now.Add(time.Minute), now.Add(2*time.Second)) {
		t.Fatal("cache did not reclaim an expired entry")
	}
}

func FuzzEnvelopeRejectsAlteredPayload(f *testing.F) {
	f.Add("v=0\r\na=fingerprint:sha-256 AA\r\n")
	f.Fuzz(func(t *testing.T, payload string) {
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		now := time.Now().UTC()
		envelope, err := NewEnvelope(t.Context(), testSigner{private: privateKey}, MessageOffer, "session", "node_"+strings.Repeat("a", 52), payload, now, time.Minute)
		if err != nil {
			t.Skip()
		}
		envelope.Payload += "x"
		if _, err := envelope.Verify(now, time.Minute); err == nil {
			t.Fatal("altered payload verified")
		}
	})
}
