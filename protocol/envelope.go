package protocol

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	Version         = "gonzb-connect/1.0"
	MessageOffer    = "offer"
	MessageAnswer   = "answer"
	MessageConnect  = "connect"
	MessageError    = "error"
	MaxMessageBytes = 128 << 10
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Signer interface {
	NodeID(context.Context) (string, error)
	PublicKey(context.Context) (ed25519.PublicKey, error)
	Sign(context.Context, []byte) ([]byte, error)
}

// Envelope signs the hash of the exact SDP payload, not a re-encoded form.
// Coordinators inspect routing metadata but never need to parse Payload.
type Envelope struct {
	ProtocolVersion string `json:"protocol_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	SourceNodeID    string `json:"source_node_id"`
	TargetNodeID    string `json:"target_node_id"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
	Nonce           string `json:"nonce"`
	PayloadSHA256   string `json:"payload_sha256"`
	SourcePublicKey string `json:"source_public_key"`
	Payload         string `json:"payload"`
	Signature       string `json:"signature"`
}

func NewEnvelope(ctx context.Context, signer Signer, messageType, sessionID, targetNodeID, payload string, now time.Time, ttl time.Duration) (Envelope, error) {
	var out Envelope
	if signer == nil {
		return out, fmt.Errorf("signer is required")
	}
	if ttl <= 0 || ttl > 2*time.Minute {
		ttl = 2 * time.Minute
	}
	nodeID, err := signer.NodeID(ctx)
	if err != nil {
		return out, err
	}
	messageType = strings.TrimSpace(messageType)
	sessionID = strings.TrimSpace(sessionID)
	if !ValidNodeID(nodeID) || !ValidNodeID(strings.TrimSpace(targetNodeID)) || !validMessageType(messageType) || !validOpaqueID(sessionID) {
		return out, fmt.Errorf("invalid signaling envelope parameters")
	}
	if err := validateSignalingPayload(messageType, payload); err != nil {
		return out, err
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return out, err
	}
	if len(publicKey) != ed25519.PublicKeySize || NodeIDFromPublicKey(publicKey) != nodeID {
		return out, fmt.Errorf("signaling signer public key does not match its node ID")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	out = Envelope{
		ProtocolVersion: Version,
		MessageType:     messageType,
		SessionID:       sessionID,
		SourceNodeID:    nodeID,
		TargetNodeID:    strings.TrimSpace(targetNodeID),
		CreatedAt:       now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:       now.UTC().Add(ttl).Format(time.RFC3339Nano),
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce),
		PayloadSHA256:   payloadHash(payload),
		SourcePublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Payload:         payload,
	}
	canonical, err := out.canonicalUnsigned()
	if err != nil {
		return Envelope{}, err
	}
	signature, err := signer.Sign(ctx, canonical)
	if err != nil {
		return Envelope{}, err
	}
	out.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return out, nil
}

func (e Envelope) Verify(now time.Time, tolerance time.Duration) (ed25519.PublicKey, error) {
	if e.ProtocolVersion != Version || !validMessageType(e.MessageType) || !validOpaqueID(e.SessionID) || !ValidNodeID(e.SourceNodeID) || !ValidNodeID(e.TargetNodeID) {
		return nil, fmt.Errorf("incomplete signaling envelope")
	}
	if err := validateSignalingPayload(e.MessageType, e.Payload); err != nil {
		return nil, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid signaling creation time")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, e.ExpiresAt)
	if err != nil || !expiresAt.After(createdAt) || expiresAt.Sub(createdAt) > 2*time.Minute || !expiresAt.After(now.UTC()) {
		return nil, fmt.Errorf("expired signaling envelope")
	}
	if tolerance <= 0 {
		tolerance = 2 * time.Minute
	}
	if createdAt.Before(now.UTC().Add(-tolerance)) || createdAt.After(now.UTC().Add(tolerance)) {
		return nil, fmt.Errorf("signaling creation time outside tolerance")
	}
	if payloadHash(e.Payload) != e.PayloadSHA256 {
		return nil, fmt.Errorf("signaling payload hash mismatch")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(e.Nonce))
	if err != nil || len(nonce) != 16 {
		return nil, fmt.Errorf("invalid signaling nonce")
	}
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(e.SourcePublicKey))
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signaling public key")
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)
	if NodeIDFromPublicKey(publicKey) != e.SourceNodeID {
		return nil, fmt.Errorf("signaling source does not match public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(e.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signaling signature")
	}
	canonical, err := e.canonicalUnsigned()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return nil, fmt.Errorf("signaling signature verification failed")
	}
	return publicKey, nil
}

func validateSignalingPayload(messageType, payload string) error {
	switch messageType {
	case MessageOffer, MessageAnswer:
		if payload == "" || len(payload) > 96<<10 {
			return fmt.Errorf("invalid signaling SDP payload")
		}
	case MessageConnect:
		if payload != "" {
			return fmt.Errorf("connect signaling payload must be empty")
		}
	case MessageError:
		if len(payload) > 1024 {
			return fmt.Errorf("signaling error payload exceeds bounds")
		}
	}
	return nil
}

func validOpaqueID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func (e Envelope) canonicalUnsigned() ([]byte, error) {
	raw, err := json.Marshal(map[string]any{
		"protocol_version":  e.ProtocolVersion,
		"message_type":      e.MessageType,
		"session_id":        e.SessionID,
		"source_node_id":    e.SourceNodeID,
		"target_node_id":    e.TargetNodeID,
		"created_at":        e.CreatedAt,
		"expires_at":        e.ExpiresAt,
		"nonce":             e.Nonce,
		"payload_sha256":    e.PayloadSHA256,
		"source_public_key": e.SourcePublicKey,
	})
	if err != nil {
		return nil, err
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize signaling envelope: %w", err)
	}
	return canonical, nil
}

func payloadHash(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func NodeIDFromPublicKey(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "node_" + strings.ToLower(base32NoPadding.EncodeToString(sum[:]))
}

func ValidNodeID(value string) bool {
	value = strings.TrimSpace(value)
	if value != strings.ToLower(value) || !strings.HasPrefix(value, "node_") || len(value) != 57 {
		return false
	}
	raw, err := base32NoPadding.DecodeString(strings.ToUpper(strings.TrimPrefix(value, "node_")))
	return err == nil && len(raw) == sha256.Size
}

func validMessageType(value string) bool {
	switch value {
	case MessageOffer, MessageAnswer, MessageConnect, MessageError:
		return true
	default:
		return false
	}
}

type ReplayCache struct {
	mu       sync.Mutex
	items    map[string]time.Time
	expiries replayExpiryHeap
	limit    int
}

const defaultReplayCacheEntries = 65536

func NewReplayCache() *ReplayCache { return NewReplayCacheWithLimit(defaultReplayCacheEntries) }

func NewReplayCacheWithLimit(limit int) *ReplayCache {
	if limit <= 0 {
		limit = defaultReplayCacheEntries
	}
	return &ReplayCache{items: make(map[string]time.Time), limit: limit}
}

func (r *ReplayCache) Consume(sourceNodeID, nonce string, expiresAt, now time.Time) bool {
	if r == nil || strings.TrimSpace(sourceNodeID) == "" || strings.TrimSpace(nonce) == "" || !expiresAt.After(now) {
		return false
	}
	key := sourceNodeID + "\x00" + nonce
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.expiries) > 0 && !r.expiries[0].expiresAt.After(now) {
		item := heap.Pop(&r.expiries).(replayExpiry)
		if current, ok := r.items[item.key]; ok && current.Equal(item.expiresAt) {
			delete(r.items, item.key)
		}
	}
	if _, exists := r.items[key]; exists {
		return false
	}
	if len(r.items) >= r.limit {
		return false
	}
	r.items[key] = expiresAt
	heap.Push(&r.expiries, replayExpiry{key: key, expiresAt: expiresAt})
	return true
}

type replayExpiry struct {
	key       string
	expiresAt time.Time
}

type replayExpiryHeap []replayExpiry

func (h replayExpiryHeap) Len() int           { return len(h) }
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h replayExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *replayExpiryHeap) Push(value any)    { *h = append(*h, value.(replayExpiry)) }
func (h *replayExpiryHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
