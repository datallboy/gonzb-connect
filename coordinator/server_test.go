package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/datallboy/gonzb-connect/protocol"
)

type fakeEnrollmentStore struct {
	mu        sync.Mutex
	bindCalls int
	bindErr   error
}

type blockingEnrollmentStore struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingEnrollmentStore) CreateEnrollment(context.Context) (string, error) {
	return validEnrollmentToken(), nil
}
func (s *blockingEnrollmentStore) BindEnrollment(context.Context, string, string, string) error {
	s.entered <- struct{}{}
	<-s.release
	return nil
}
func (*blockingEnrollmentStore) RevokeEnrollment(context.Context, string) (bool, error) {
	return true, nil
}

func (*fakeEnrollmentStore) CreateEnrollment(context.Context) (string, error) {
	return validEnrollmentToken(), nil
}
func (s *fakeEnrollmentStore) BindEnrollment(context.Context, string, string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindCalls++
	return s.bindErr
}
func (*fakeEnrollmentStore) RevokeEnrollment(context.Context, string) (bool, error) {
	return true, nil
}

func TestTURNCredentialsBlindNodeIDAndMatchRESTSecret(t *testing.T) {
	store := &fakeEnrollmentStore{}
	secret := strings.Repeat("t", 32)
	server := NewServer(store, Config{
		TURNSecret: secret, TURNURIs: []string{"turn:203.0.113.1:3478?transport=udp"},
		STUNURIs: []string{"stun:203.0.113.1:3478"}, TURNCredentialTTL: time.Minute,
	})
	nodeID, publicKey := testNodeIdentity(t)
	request := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("TURN credential status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Username   string `json:"username"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.Username, nodeID) {
		t.Fatal("TURN username disclosed the persistent node ID")
	}
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write([]byte(response.Username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(response.Credential), []byte(want)) {
		t.Fatal("TURN credential did not match coturn REST authentication")
	}
}

func TestAuthenticationRateAndStrictBearerParsing(t *testing.T) {
	store := &fakeEnrollmentStore{}
	server := NewServer(store, Config{TURNSecret: strings.Repeat("t", 32), AuthAttemptsPerMinute: 1})
	nodeID, publicKey := testNodeIdentity(t)
	first := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	first.RemoteAddr = "198.51.100.5:1000"
	firstResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstResult, first)
	if firstResult.Code != http.StatusOK {
		t.Fatalf("first authentication status = %d", firstResult.Code)
	}
	second := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	second.RemoteAddr = first.RemoteAddr
	secondResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondResult, second)
	if secondResult.Code != http.StatusUnauthorized {
		t.Fatalf("rate-limited authentication status = %d", secondResult.Code)
	}
	store.mu.Lock()
	bindCalls := store.bindCalls
	store.mu.Unlock()
	if bindCalls != 1 {
		t.Fatalf("expensive token verification called %d times", bindCalls)
	}

	strictServer := NewServer(store, Config{TURNSecret: strings.Repeat("t", 32)})
	bad := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	bad.Header.Set("Authorization", "bearer "+validEnrollmentToken())
	badResult := httptest.NewRecorder()
	strictServer.Handler().ServeHTTP(badResult, bad)
	if badResult.Code != http.StatusUnauthorized {
		t.Fatal("non-canonical Bearer authorization was accepted")
	}
}

func TestGlobalAuthenticationLimitPrecedesKeyedLimits(t *testing.T) {
	store := &fakeEnrollmentStore{}
	server := NewServer(store, Config{
		TURNSecret: strings.Repeat("t", 32), GlobalAuthPerMinute: 1, AuthAttemptsPerMinute: 60,
	})
	nodeID, publicKey := testNodeIdentity(t)
	first := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	first.RemoteAddr = "198.51.100.10:1000"
	firstResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstResult, first)
	if firstResult.Code != http.StatusOK {
		t.Fatalf("first authentication status = %d", firstResult.Code)
	}
	server.authLimiter.mu.Lock()
	before := len(server.authLimiter.items)
	server.authLimiter.mu.Unlock()

	second := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	second.RemoteAddr = "198.51.100.11:1000"
	secondResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondResult, second)
	if secondResult.Code != http.StatusUnauthorized {
		t.Fatalf("globally limited authentication status = %d", secondResult.Code)
	}
	server.authLimiter.mu.Lock()
	after := len(server.authLimiter.items)
	server.authLimiter.mu.Unlock()
	if after != before {
		t.Fatalf("globally rejected request grew keyed limiter state: before=%d after=%d", before, after)
	}
}

func TestDefaultAuthenticationConcurrencyIsMemoryBounded(t *testing.T) {
	store := &blockingEnrollmentStore{entered: make(chan struct{}, 2), release: make(chan struct{})}
	server := NewServer(store, Config{TURNSecret: strings.Repeat("t", 32)})
	nodeID, publicKey := testNodeIdentity(t)

	results := make(chan int, 2)
	request := func() {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken()))
		results <- recorder.Code
	}
	go request()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("authentication operation did not acquire the default limit")
	}

	go request()
	select {
	case <-store.entered:
		t.Fatal("second Argon2 verification ran concurrently with the first")
	case <-time.After(50 * time.Millisecond):
	}
	close(store.release)
	for range 2 {
		if status := <-results; status != http.StatusOK {
			t.Fatalf("queued authentication status = %d", status)
		}
	}
}

func TestAuthenticationQueueIsBounded(t *testing.T) {
	store := &blockingEnrollmentStore{entered: make(chan struct{}, 16), release: make(chan struct{})}
	server := NewServer(store, Config{TURNSecret: strings.Repeat("t", 32), MaxConcurrentAuth: 1})
	nodeID, publicKey := testNodeIdentity(t)
	results := make(chan int, cap(server.authQueue))

	request := func() {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken()))
		results <- recorder.Code
	}
	for range cap(server.authQueue) {
		go request()
	}
	deadline := time.Now().Add(time.Second)
	for len(server.authQueue) != cap(server.authQueue) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.authQueue) != cap(server.authQueue) {
		t.Fatal("authentication queue did not fill")
	}

	overflow := httptest.NewRecorder()
	server.Handler().ServeHTTP(overflow, authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken()))
	if overflow.Code != http.StatusUnauthorized {
		t.Fatalf("overflow authentication status = %d", overflow.Code)
	}
	close(store.release)
	for range cap(server.authQueue) {
		if status := <-results; status != http.StatusOK {
			t.Fatalf("queued authentication status = %d", status)
		}
	}
}

func TestWebSocketOriginsAreDefaultDenyForBrowsers(t *testing.T) {
	server := NewServer(nil, Config{AllowedOrigins: []string{"https://console.example"}})
	request := httptest.NewRequest(http.MethodGet, "https://connect.example/v1/signal", nil)
	request.Header.Set("Origin", "https://evil.example")
	if server.upgrader.CheckOrigin(request) {
		t.Fatal("unlisted browser origin was accepted")
	}
	request.Header.Set("Origin", "https://console.example")
	if !server.upgrader.CheckOrigin(request) {
		t.Fatal("listed browser origin was rejected")
	}
	request.Header.Del("Origin")
	if !server.upgrader.CheckOrigin(request) {
		t.Fatal("non-browser client without Origin was rejected")
	}
}

func TestValidateConfigRejectsWeakSecretsAndInvalidServers(t *testing.T) {
	valid := Config{
		AdminToken: strings.Repeat("a", 32), TURNSecret: strings.Repeat("t", 32),
		STUNURIs: []string{"stun:stun.example:3478"}, TURNURIs: []string{"turns:turn.example:5349?transport=tcp"},
	}
	if err := ValidateConfig(valid); err != nil {
		t.Fatal(err)
	}
	weak := valid
	weak.AdminToken = "short"
	if ValidateConfig(weak) == nil {
		t.Fatal("weak admin secret was accepted")
	}
	invalidURI := valid
	invalidURI.TURNURIs = []string{"http://turn.example"}
	if ValidateConfig(invalidURI) == nil {
		t.Fatal("non-TURN server URI was accepted")
	}
}

func TestFixedWindowLimiterBoundsCountBytesAndKeys(t *testing.T) {
	now := time.Now().UTC()
	limiter := newFixedWindowLimiter(1)
	if !limiter.allow("node-a", 2, 10, 5, now) {
		t.Fatal("limiter rejected the first item")
	}
	if !limiter.allow("node-a", 2, 10, 5, now) {
		t.Fatal("limiter rejected traffic before its boundary")
	}
	if limiter.allow("node-a", 2, 10, 0, now) || limiter.allow("node-b", 2, 10, 1, now) {
		t.Fatal("limiter exceeded a count or key boundary")
	}
	if !limiter.allow("node-b", 2, 10, 1, now.Add(time.Minute)) {
		t.Fatal("limiter did not reclaim an expired key")
	}
}

func TestMetricsRequireAdminAndContainOnlyAggregateNames(t *testing.T) {
	server := NewServer(&fakeEnrollmentStore{}, Config{
		AdminToken: strings.Repeat("a", 32), TURNSecret: strings.Repeat("t", 32),
	})
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized metrics status = %d", unauthorized.Code)
	}

	nodeID, publicKey := testNodeIdentity(t)
	auth := authenticatedRequest(t, nodeID, publicKey, validEnrollmentToken())
	result := httptest.NewRecorder()
	server.Handler().ServeHTTP(result, auth)
	if result.Code != http.StatusOK {
		t.Fatalf("authenticated request status = %d", result.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics, request)
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", metrics.Code)
	}
	body := metrics.Body.String()
	for _, expected := range []string{"gonzb_connect_auth_succeeded_total 1", "gonzb_connect_active_registrations 0"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics omit %q:\n%s", expected, body)
		}
	}
	for _, prohibited := range []string{nodeID, publicKey, validEnrollmentToken(), "candidate", "fingerprint"} {
		if strings.Contains(body, prohibited) {
			t.Fatalf("metrics disclose prohibited value %q", prohibited)
		}
	}
}

func testNodeIdentity(t *testing.T) (string, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NodeIDFromPublicKey(publicKey), base64.RawURLEncoding.EncodeToString(publicKey)
}

func authenticatedRequest(t *testing.T, nodeID, publicKey, token string) *http.Request {
	t.Helper()
	query := url.Values{"node_id": []string{nodeID}, "public_key": []string{publicKey}}
	request := httptest.NewRequest(http.MethodGet, "https://connect.example/v1/turn-credentials?"+query.Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func validEnrollmentToken() string {
	return "gzc_" + base64.RawURLEncoding.EncodeToString(make([]byte, 12)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}
