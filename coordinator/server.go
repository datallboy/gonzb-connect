package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- coturn REST authentication requires HMAC-SHA1; this is not password hashing.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/datallboy/gonzb-connect/protocol"
	"github.com/gorilla/websocket"
)

type Config struct {
	AdminToken                 string
	TURNSecret                 string
	TURNURIs                   []string
	STUNURIs                   []string
	TURNCredentialTTL          time.Duration
	MaxRegistrationsPerNode    int
	MaxNegotiationsPerNode     int
	NegotiationsPerMinute      int
	MaxMessageBytes            int64
	MessagesPerMinute          int
	SignalBytesPerMinute       int64
	GlobalMessagesPerMinute    int
	GlobalSignalBytesPerMinute int64
	AuthAttemptsPerMinute      int
	GlobalAuthPerMinute        int
	MaxConcurrentAuth          int
	MaxInvalidMessages         int
	MaxTotalRegistrations      int
	ReplayCacheEntries         int
	WebSocketReadTimeout       time.Duration
	WebSocketPingInterval      time.Duration
	AllowedOrigins             []string
	TrustProxyHeaders          bool
}

type EnrollmentStore interface {
	CreateEnrollment(context.Context) (string, error)
	BindEnrollment(context.Context, string, string, string) error
	RevokeEnrollment(context.Context, string) (bool, error)
}

type Server struct {
	store         EnrollmentStore
	cfg           Config
	upgrader      websocket.Upgrader
	mu            sync.Mutex
	registrations map[string]map[*registration]struct{}
	sessions      map[string]session
	rates         map[string]rateWindow
	replay        *protocol.ReplayCache
	authLimiter   *fixedWindowLimiter
	messageLimit  *fixedWindowLimiter
	authSem       chan struct{}
	authQueue     chan struct{}
	metrics       serverMetrics
}

type registration struct {
	nodeID    string
	publicKey string
	tokenID   string
	conn      *websocket.Conn
	writeMu   sync.Mutex
	stopPing  chan struct{}
}

type session struct {
	source, target string
	expiresAt      time.Time
}

type rateWindow struct {
	started time.Time
	count   int
}

func NewServer(store EnrollmentStore, cfg Config) *Server {
	if cfg.TURNCredentialTTL <= 0 || cfg.TURNCredentialTTL > 10*time.Minute {
		cfg.TURNCredentialTTL = 10 * time.Minute
	}
	if cfg.MaxRegistrationsPerNode <= 0 {
		cfg.MaxRegistrationsPerNode = 2
	}
	if cfg.MaxNegotiationsPerNode <= 0 {
		cfg.MaxNegotiationsPerNode = 8
	}
	if cfg.NegotiationsPerMinute <= 0 {
		cfg.NegotiationsPerMinute = 30
	}
	if cfg.MaxMessageBytes <= 0 || cfg.MaxMessageBytes > protocol.MaxMessageBytes {
		cfg.MaxMessageBytes = protocol.MaxMessageBytes
	}
	if cfg.MessagesPerMinute <= 0 {
		cfg.MessagesPerMinute = 120
	}
	if cfg.SignalBytesPerMinute <= 0 {
		cfg.SignalBytesPerMinute = 4 << 20
	}
	if cfg.GlobalMessagesPerMinute <= 0 {
		cfg.GlobalMessagesPerMinute = 10000
	}
	if cfg.GlobalSignalBytesPerMinute <= 0 {
		cfg.GlobalSignalBytesPerMinute = 128 << 20
	}
	if cfg.AuthAttemptsPerMinute <= 0 {
		cfg.AuthAttemptsPerMinute = 60
	}
	if cfg.GlobalAuthPerMinute <= 0 {
		cfg.GlobalAuthPerMinute = 600
	}
	if cfg.MaxConcurrentAuth <= 0 {
		// Each Argon2id verification allocates 64 MiB. Serialize by default so
		// an otherwise-correct deployment cannot be OOM-killed merely because
		// several nodes reconnect at once. Larger containers may opt into more.
		cfg.MaxConcurrentAuth = 1
	}
	if cfg.MaxInvalidMessages <= 0 {
		cfg.MaxInvalidMessages = 8
	}
	if cfg.MaxTotalRegistrations <= 0 {
		cfg.MaxTotalRegistrations = 4096
	}
	if cfg.ReplayCacheEntries <= 0 {
		cfg.ReplayCacheEntries = 65536
	}
	if cfg.WebSocketReadTimeout <= 0 {
		cfg.WebSocketReadTimeout = 90 * time.Second
	}
	if cfg.WebSocketPingInterval <= 0 || cfg.WebSocketPingInterval >= cfg.WebSocketReadTimeout {
		cfg.WebSocketPingInterval = 30 * time.Second
	}
	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		allowedOrigins[strings.TrimRight(strings.TrimSpace(origin), "/")] = struct{}{}
	}
	if cfg.MaxConcurrentAuth > 16 {
		cfg.MaxConcurrentAuth = 16
	}
	authQueueCapacity := cfg.MaxConcurrentAuth * 2
	if authQueueCapacity < 16 {
		authQueueCapacity = 16
	}
	return &Server{
		store: store, cfg: cfg, registrations: make(map[string]map[*registration]struct{}),
		sessions: make(map[string]session), rates: make(map[string]rateWindow), replay: protocol.NewReplayCacheWithLimit(cfg.ReplayCacheEntries),
		authLimiter: newFixedWindowLimiter(65536), messageLimit: newFixedWindowLimiter(65536),
		authSem: make(chan struct{}, cfg.MaxConcurrentAuth), authQueue: make(chan struct{}, authQueueCapacity),
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			if len(r.Header.Values("Origin")) > 1 {
				return false
			}
			origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
			if origin == "" {
				return true
			}
			_, ok := allowedOrigins[origin]
			return ok
		}},
	}
}

func ValidateConfig(cfg Config) error {
	if len([]byte(strings.TrimSpace(cfg.AdminToken))) < 32 {
		return fmt.Errorf("admin token must contain at least 32 bytes")
	}
	if len([]byte(strings.TrimSpace(cfg.TURNSecret))) < 32 {
		return fmt.Errorf("TURN shared secret must contain at least 32 bytes")
	}
	if len(cfg.STUNURIs) == 0 || len(cfg.STUNURIs) > 2 || len(cfg.TURNURIs) == 0 || len(cfg.TURNURIs) > 4 {
		return fmt.Errorf("one or two STUN URIs and one to four TURN URIs are required")
	}
	for _, raw := range cfg.STUNURIs {
		if err := validateServerURI(raw, false); err != nil {
			return err
		}
	}
	for _, raw := range cfg.TURNURIs {
		if err := validateServerURI(raw, true); err != nil {
			return err
		}
	}
	for _, raw := range cfg.AllowedOrigins {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("allowed WebSocket origins must be absolute HTTPS origins")
		}
	}
	return nil
}

func validateServerURI(raw string, turn bool) error {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque == "" || strings.ContainsAny(parsed.Opaque, "@/#") {
		return fmt.Errorf("invalid ICE server URI")
	}
	if turn {
		if parsed.Scheme != "turn" && parsed.Scheme != "turns" {
			return fmt.Errorf("TURN URI must use turn or turns")
		}
		if parsed.RawQuery != "" {
			values := parsed.Query()["transport"]
			if len(parsed.Query()) != 1 || len(values) != 1 || (values[0] != "udp" && values[0] != "tcp") {
				return fmt.Errorf("TURN URI contains an invalid transport")
			}
		}
	} else if (parsed.Scheme != "stun" && parsed.Scheme != "stuns") || parsed.RawQuery != "" {
		return fmt.Errorf("STUN URI must use stun or stuns without a query")
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/admin/enrollments", s.createEnrollment)
	mux.HandleFunc("DELETE /v1/admin/enrollments/{token_id}", s.revokeEnrollment)
	mux.HandleFunc("GET /v1/admin/metrics", s.metricsHandler)
	mux.HandleFunc("GET /v1/turn-credentials", s.turnCredentials)
	mux.HandleFunc("GET /v1/signal", s.signal)
	return http.MaxBytesHandler(mux, s.cfg.MaxMessageBytes)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	token, err := s.store.CreateEnrollment(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create enrollment failed"})
		return
	}
	tokenID, _, _ := parseToken(token)
	writeJSON(w, http.StatusCreated, map[string]string{"token_id": tokenID, "token": token})
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	tokenID := r.PathValue("token_id")
	if len(tokenID) != 16 || !validTokenPart(tokenID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	revoked, err := s.store.RevokeEnrollment(r.Context(), tokenID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke enrollment failed"})
		return
	}
	if !revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.closeTokenRegistrations(tokenID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) turnCredentials(w http.ResponseWriter, r *http.Request) {
	nodeID, _, _, _, err := s.authenticateRegistration(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment"})
		return
	}
	expires := time.Now().UTC().Add(s.cfg.TURNCredentialTTL).Unix()
	accountMAC := hmac.New(sha256.New, []byte(s.cfg.TURNSecret))
	_, _ = accountMAC.Write([]byte("turn-account\x00" + nodeID))
	account := base64.RawURLEncoding.EncodeToString(accountMAC.Sum(nil)[:18])
	username := strconv.FormatInt(expires, 10) + ":" + account
	mac := hmac.New(sha1.New, []byte(s.cfg.TURNSecret))
	_, _ = mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	writeJSON(w, http.StatusOK, map[string]any{
		"username": username, "credential": credential,
		"ttl_seconds": int(s.cfg.TURNCredentialTTL.Seconds()),
		"uris":        s.cfg.TURNURIs, "stun_uris": s.cfg.STUNURIs,
	})
}

func (s *Server) signal(w http.ResponseWriter, r *http.Request) {
	nodeID, publicKey, _, tokenID, err := s.authenticateRegistration(r)
	if err != nil {
		http.Error(w, "invalid enrollment", http.StatusUnauthorized)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(s.cfg.MaxMessageBytes)
	registration := &registration{nodeID: nodeID, publicKey: publicKey, tokenID: tokenID, conn: conn, stopPing: make(chan struct{})}
	if !s.addRegistration(registration) {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "registration quota exceeded"), time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.WebSocketReadTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(s.cfg.WebSocketReadTimeout))
	})
	go s.pingRegistration(registration)
	defer func() {
		close(registration.stopPing)
		s.removeRegistration(registration)
		_ = conn.Close()
	}()
	invalidMessages := 0
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage || int64(len(payload)) > s.cfg.MaxMessageBytes ||
			!s.messageLimit.allow("node:"+nodeID, s.cfg.MessagesPerMinute, s.cfg.SignalBytesPerMinute, int64(len(payload)), time.Now().UTC()) ||
			!s.messageLimit.allow("global", s.cfg.GlobalMessagesPerMinute, s.cfg.GlobalSignalBytesPerMinute, int64(len(payload)), time.Now().UTC()) {
			s.metrics.signalingRejected.Add(1)
			s.closeRegistration(registration, "signaling rate or size limit exceeded")
			return
		}
		var envelope protocol.Envelope
		if decodeEnvelope(payload, &envelope) != nil {
			s.metrics.signalingRejected.Add(1)
			invalidMessages++
			if invalidMessages >= s.cfg.MaxInvalidMessages {
				s.closeRegistration(registration, "too many invalid signaling messages")
				return
			}
			continue
		}
		verifiedKey, err := envelope.Verify(time.Now().UTC(), 2*time.Minute)
		if err != nil || envelope.SourceNodeID != nodeID || base64.RawURLEncoding.EncodeToString(verifiedKey) != publicKey {
			s.metrics.signalingRejected.Add(1)
			invalidMessages++
			if invalidMessages >= s.cfg.MaxInvalidMessages {
				s.closeRegistration(registration, "too many invalid signaling messages")
				return
			}
			continue
		}
		expiresAt, _ := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
		if !s.replay.Consume(nodeID, envelope.Nonce, expiresAt, time.Now().UTC()) {
			s.metrics.signalingRejected.Add(1)
			invalidMessages++
			if invalidMessages >= s.cfg.MaxInvalidMessages {
				s.closeRegistration(registration, "too many invalid signaling messages")
				return
			}
			continue
		}
		if (envelope.MessageType == protocol.MessageOffer || envelope.MessageType == protocol.MessageConnect) && !s.allowNegotiationRate(nodeID) {
			s.metrics.signalingRejected.Add(1)
			s.metrics.negotiationsRejected.Add(1)
			s.closeRegistration(registration, "negotiation rate exceeded")
			return
		}
		if !s.trackNegotiation(envelope) {
			s.metrics.signalingRejected.Add(1)
			s.metrics.negotiationsRejected.Add(1)
			invalidMessages++
			if invalidMessages >= s.cfg.MaxInvalidMessages {
				s.closeRegistration(registration, "too many invalid signaling messages")
				return
			}
			continue
		}
		s.metrics.signalingAccepted.Add(1)
		s.route(envelope.TargetNodeID, payload)
	}
}

func (s *Server) trackNegotiation(envelope protocol.Envelope) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, current := range s.sessions {
		if !current.expiresAt.After(now) {
			delete(s.sessions, id)
		}
	}
	s.metrics.activeNegotiations.Store(int64(len(s.sessions)))
	if envelope.MessageType == protocol.MessageOffer || envelope.MessageType == protocol.MessageConnect {
		activeSource := 0
		activeTarget := 0
		for _, current := range s.sessions {
			if current.source == envelope.SourceNodeID || current.target == envelope.SourceNodeID {
				activeSource++
			}
			if current.source == envelope.TargetNodeID || current.target == envelope.TargetNodeID {
				activeTarget++
			}
		}
		if activeSource >= s.cfg.MaxNegotiationsPerNode || activeTarget >= s.cfg.MaxNegotiationsPerNode {
			return false
		}
		if envelope.MessageType == protocol.MessageConnect {
			return true
		}
		if _, exists := s.sessions[envelope.SessionID]; exists {
			return false
		}
		expiresAt := now.Add(2 * time.Minute)
		s.sessions[envelope.SessionID] = session{source: envelope.SourceNodeID, target: envelope.TargetNodeID, expiresAt: expiresAt}
		s.metrics.activeNegotiations.Store(int64(len(s.sessions)))
		sessionID := envelope.SessionID
		time.AfterFunc(time.Until(expiresAt), func() {
			s.mu.Lock()
			if current, ok := s.sessions[sessionID]; ok && !current.expiresAt.After(time.Now().UTC()) {
				delete(s.sessions, sessionID)
				s.metrics.activeNegotiations.Store(int64(len(s.sessions)))
			}
			s.mu.Unlock()
		})
		return true
	}
	current, ok := s.sessions[envelope.SessionID]
	if !ok || current.source != envelope.TargetNodeID || current.target != envelope.SourceNodeID {
		return false
	}
	if envelope.MessageType == protocol.MessageAnswer {
		delete(s.sessions, envelope.SessionID)
		s.metrics.activeNegotiations.Store(int64(len(s.sessions)))
	}
	return true
}

func (s *Server) route(targetNodeID string, payload []byte) {
	s.mu.Lock()
	targets := make([]*registration, 0, len(s.registrations[targetNodeID]))
	for registration := range s.registrations[targetNodeID] {
		targets = append(targets, registration)
	}
	s.mu.Unlock()
	if len(targets) == 0 {
		s.metrics.offlineTargets.Add(1)
	}
	for _, target := range targets {
		target.writeMu.Lock()
		_ = target.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := target.conn.WriteMessage(websocket.TextMessage, payload)
		target.writeMu.Unlock()
		if err != nil {
			_ = target.conn.Close()
			continue
		}
		s.metrics.signalingDelivered.Add(1)
		s.metrics.signalingBytesDelivered.Add(uint64(len(payload)))
	}
}

func (s *Server) addRegistration(item *registration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, registrations := range s.registrations {
		total += len(registrations)
	}
	if total >= s.cfg.MaxTotalRegistrations {
		s.metrics.registrationsRejected.Add(1)
		return false
	}
	items := s.registrations[item.nodeID]
	if len(items) >= s.cfg.MaxRegistrationsPerNode {
		s.metrics.registrationsRejected.Add(1)
		return false
	}
	if items == nil {
		items = make(map[*registration]struct{})
		s.registrations[item.nodeID] = items
	}
	items[item] = struct{}{}
	s.metrics.activeRegistrations.Add(1)
	return true
}

func (s *Server) pingRegistration(item *registration) {
	ticker := time.NewTicker(s.cfg.WebSocketPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-item.stopPing:
			return
		case <-ticker.C:
			item.writeMu.Lock()
			err := item.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			item.writeMu.Unlock()
			if err != nil {
				_ = item.conn.Close()
				return
			}
		}
	}
}

func (s *Server) closeRegistration(item *registration, reason string) {
	item.writeMu.Lock()
	_ = item.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason), time.Now().Add(time.Second))
	item.writeMu.Unlock()
}

func (s *Server) removeRegistration(registration *registration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.registrations[registration.nodeID][registration]; exists {
		delete(s.registrations[registration.nodeID], registration)
		s.metrics.activeRegistrations.Add(-1)
	}
	if len(s.registrations[registration.nodeID]) == 0 {
		delete(s.registrations, registration.nodeID)
	}
}

func (s *Server) closeTokenRegistrations(tokenID string) {
	s.mu.Lock()
	items := make([]*registration, 0)
	for _, registrations := range s.registrations {
		for item := range registrations {
			if item.tokenID == tokenID {
				items = append(items, item)
			}
		}
	}
	s.mu.Unlock()
	for _, item := range items {
		item.writeMu.Lock()
		_ = item.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "enrollment revoked"), time.Now().Add(time.Second))
		_ = item.conn.Close()
		item.writeMu.Unlock()
	}
}

func (s *Server) allowNegotiationRate(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for key, current := range s.rates {
		if now.Sub(current.started) >= time.Minute {
			delete(s.rates, key)
		}
	}
	window := s.rates[nodeID]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = rateWindow{started: now}
	}
	if window.count >= s.cfg.NegotiationsPerMinute {
		return false
	}
	window.count++
	s.rates[nodeID] = window
	return true
}

func (s *Server) authenticateRegistration(r *http.Request) (string, string, string, string, error) {
	nodeID, publicKey, token, err := registrationCredentials(r)
	if err != nil || s.store == nil {
		s.metrics.authRejected.Add(1)
		return "", "", "", "", fmt.Errorf("invalid enrollment")
	}
	tokenID, _, err := parseToken(token)
	if err != nil {
		s.metrics.authRejected.Add(1)
		return "", "", "", "", fmt.Errorf("invalid enrollment")
	}
	now := time.Now().UTC()
	remote := remoteAddress(r, s.cfg.TrustProxyHeaders)
	// Apply the global gate first so requests rejected by the global budget
	// cannot consume arbitrary per-source or per-token limiter keys.
	if !s.authLimiter.allow("global", s.cfg.GlobalAuthPerMinute, 0, 0, now) ||
		!s.authLimiter.allow("ip:"+remote, s.cfg.AuthAttemptsPerMinute, 0, 0, now) ||
		!s.authLimiter.allow("token:"+tokenID, s.cfg.AuthAttemptsPerMinute, 0, 0, now) {
		s.metrics.authRejected.Add(1)
		return "", "", "", "", fmt.Errorf("authentication rate exceeded")
	}
	select {
	case s.authQueue <- struct{}{}:
		defer func() { <-s.authQueue }()
	default:
		s.metrics.authRejected.Add(1)
		return "", "", "", "", fmt.Errorf("authentication queue exceeded")
	}
	select {
	case s.authSem <- struct{}{}:
		defer func() { <-s.authSem }()
	case <-r.Context().Done():
		s.metrics.authRejected.Add(1)
		return "", "", "", "", r.Context().Err()
	}
	if err := s.store.BindEnrollment(r.Context(), token, nodeID, publicKey); err != nil {
		s.metrics.authRejected.Add(1)
		return "", "", "", "", fmt.Errorf("invalid enrollment")
	}
	s.metrics.authSucceeded.Add(1)
	return nodeID, publicKey, token, tokenID, nil
}

func registrationCredentials(r *http.Request) (string, string, string, error) {
	query := r.URL.Query()
	if len(query["node_id"]) != 1 || len(query["public_key"]) != 1 {
		return "", "", "", fmt.Errorf("invalid registration identity")
	}
	nodeID := query["node_id"][0]
	publicKey := query["public_key"][0]
	token, err := bearerToken(r)
	if err != nil {
		return "", "", "", err
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize || protocol.NodeIDFromPublicKey(ed25519.PublicKey(keyBytes)) != nodeID {
		return "", "", "", fmt.Errorf("invalid registration identity")
	}
	return nodeID, publicKey, token, nil
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	provided, err := bearerToken(r)
	if err != nil {
		return false
	}
	expected := strings.TrimSpace(s.cfg.AdminToken)
	return expected != "" && len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", fmt.Errorf("invalid bearer authorization")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("invalid bearer authorization")
	}
	return token, nil
}

func remoteAddress(r *http.Request, trustProxy bool) string {
	if trustProxy {
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		if net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func decodeEnvelope(payload []byte, envelope *protocol.Envelope) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(envelope); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("signaling message contains trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func ShutdownServer(ctx context.Context, server *http.Server) error { return server.Shutdown(ctx) }
