// Command gonzb-connect-lab-peer is a qualification workload for the real
// signaling, ICE, DTLS, SCTP, and DataChannel stack. It is intentionally kept
// out of the production coordinator image.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	connectclient "github.com/datallboy/gonzb-connect/client"
	connectice "github.com/datallboy/gonzb-connect/ice"
	"github.com/datallboy/gonzb-connect/protocol"
)

const maxSecretFileBytes = 64 << 10

type diskIdentity struct{ privateKey ed25519.PrivateKey }

func (d *diskIdentity) NodeID(context.Context) (string, error) {
	if d == nil || len(d.privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("lab identity is unavailable")
	}
	return protocol.NodeIDFromPublicKey(d.privateKey.Public().(ed25519.PublicKey)), nil
}

func (d *diskIdentity) PublicKey(context.Context) (ed25519.PublicKey, error) {
	if d == nil || len(d.privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("lab identity is unavailable")
	}
	return append(ed25519.PublicKey(nil), d.privateKey.Public().(ed25519.PublicKey)...), nil
}

func (d *diskIdentity) Sign(_ context.Context, payload []byte) ([]byte, error) {
	if d == nil || len(d.privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("lab identity is unavailable")
	}
	return ed25519.Sign(d.privateKey, payload), nil
}

type commonOptions struct {
	identityFile   string
	credentialFile string
	coordinator    string
	iceHosts       string
	allowTURN      bool
	basePath       string
	gatherTimeout  time.Duration
	connectTimeout time.Duration
	requestTimeout time.Duration
	idleTimeout    time.Duration
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "identity":
		err = runIdentity(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "load":
		err = runLoad(os.Args[2:])
	case "turn-credentials":
		err = runTURNCredentials(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Printf("lab peer failed: %s", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gonzb-connect-lab-peer {identity|serve|load|turn-credentials} [flags]")
	os.Exit(2)
}

func runTURNCredentials(args []string) error {
	flags := flag.NewFlagSet("turn-credentials", flag.ContinueOnError)
	identityFile := flags.String("identity-file", "", "persistent Ed25519 identity file")
	credentialFile := flags.String("credential-file", "", "coordinator enrollment credential file")
	coordinatorURL := flags.String("coordinator", "", "HTTPS coordinator base URL")
	iceHosts := flags.String("ice-server-hosts", "", "comma-separated STUN/TURN hostname allowlist")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *identityFile == "" || *credentialFile == "" || *coordinatorURL == "" {
		return fmt.Errorf("identity-file, credential-file, and coordinator are required")
	}
	identity, err := loadIdentity(*identityFile)
	if err != nil {
		return err
	}
	credential, err := readRequiredFile(*credentialFile, maxSecretFileBytes)
	if err != nil {
		return err
	}
	hosts := splitCSV(*iceHosts)
	if len(hosts) == 0 {
		return fmt.Errorf("ice-server-hosts is required")
	}
	client := connectclient.New(*coordinatorURL, string(credential), identity)
	client.SetAllowPrivateICEServers(true)
	client.SetAllowedICEServerHosts(hosts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.FetchTURNCredentials(ctx)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, response)
}

func runIdentity(args []string) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	fileName := flags.String("identity-file", "", "persistent Ed25519 identity file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*fileName) == "" {
		return fmt.Errorf("identity-file is required")
	}
	identity, created, err := loadOrCreateIdentity(*fileName)
	if err != nil {
		return err
	}
	nodeID, _ := identity.NodeID(context.Background())
	return writeJSON(os.Stdout, map[string]any{"node_id": nodeID, "created": created})
}

func addCommonFlags(flags *flag.FlagSet, options *commonOptions) {
	flags.StringVar(&options.identityFile, "identity-file", "", "persistent Ed25519 identity file")
	flags.StringVar(&options.credentialFile, "credential-file", "", "coordinator enrollment credential file")
	flags.StringVar(&options.coordinator, "coordinator", "", "HTTPS coordinator base URL")
	flags.StringVar(&options.iceHosts, "ice-server-hosts", "", "comma-separated STUN/TURN hostname allowlist")
	flags.BoolVar(&options.allowTURN, "allow-turn", true, "allow TURN relay candidates")
	flags.StringVar(&options.basePath, "base-path", "/gonzbnet/v1", "allowed traversal base path")
	flags.DurationVar(&options.gatherTimeout, "gather-timeout", 10*time.Second, "ICE gathering timeout")
	flags.DurationVar(&options.connectTimeout, "connect-timeout", 20*time.Second, "ICE connection timeout")
	flags.DurationVar(&options.requestTimeout, "request-timeout", 60*time.Second, "per-request timeout")
	flags.DurationVar(&options.idleTimeout, "idle-timeout", 2*time.Minute, "idle PeerConnection timeout")
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var options commonOptions
	addCommonFlags(flags, &options)
	listen := flags.String("listen", ":8080", "health/status listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, identity, err := newManager(options)
	if err != nil {
		return err
	}
	defer manager.Close()
	manager.SetHandler(labHandler())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := manager.Start(ctx); err != nil {
		return err
	}
	nodeID, err := identity.NodeID(ctx)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		status := manager.Status()
		ready := coordinatorReady(status)
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		writeHTTPJSON(w, code, map[string]any{"ready": ready, "node_id": status.NodeID})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusOK, manager.Status())
	})
	server := &http.Server{
		Addr: *listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := writeJSON(os.Stdout, map[string]any{"event": "listening", "node_id": nodeID, "address": *listen}); err != nil {
		return err
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type loadResult struct {
	NodeID            string            `json:"node_id"`
	TargetNodeID      string            `json:"target_node_id"`
	ExpectedPath      string            `json:"expected_path"`
	RequestsSucceeded int64             `json:"requests_succeeded"`
	RecoveredRequests int64             `json:"requests_succeeded_after_failure"`
	RequestsFailed    int64             `json:"requests_failed"`
	DurationMS        int64             `json:"duration_ms"`
	RequestsPerSecond float64           `json:"requests_per_second"`
	Status            connectice.Status `json:"status"`
}

func runLoad(args []string) error {
	flags := flag.NewFlagSet("load", flag.ContinueOnError)
	var options commonOptions
	addCommonFlags(flags, &options)
	target := flags.String("target", "", "gonzb+ice target base locator")
	requestCount := flags.Int64("requests", 100, "total requests; zero means run until duration")
	concurrency := flags.Int("concurrency", 8, "concurrent workers")
	bodyBytes := flags.Int("body-bytes", 16<<10, "deterministic request body size")
	duration := flags.Duration("duration", 0, "optional load duration")
	requestRate := flags.Float64("rate", 0, "maximum aggregate request starts per second; zero is unlimited")
	gossipEvery := flags.Int64("gossip-every", 10, "use persistent gossip for every Nth request; zero disables")
	maxFailures := flags.Int64("max-failures", 0, "maximum tolerated request failures during an injected fault")
	expectedPath := flags.String("expected-path", "any", "required selected path: any, direct, or relay")
	canaryFile := flags.String("canary-file", "", "optional per-run payload canary file")
	apiCanaryFile := flags.String("api-canary-file", "", "optional per-run Authorization canary file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *target == "" || (*expectedPath != "any" && *expectedPath != "direct" && *expectedPath != "relay") {
		return fmt.Errorf("target and a valid expected-path are required")
	}
	if *concurrency < 1 || *concurrency > 64 || *bodyBytes < 0 || *bodyBytes > 128<<20 || *requestCount < 0 ||
		*gossipEvery < 0 || *requestRate < 0 || *requestRate > 1000 || *maxFailures < 0 || *maxFailures > 1024 {
		return fmt.Errorf("load bounds are invalid")
	}
	if *requestCount == 0 && *duration <= 0 {
		return fmt.Errorf("duration is required when requests is zero")
	}
	canary, err := readOptionalFile(*canaryFile, 4096)
	if err != nil {
		return err
	}
	apiCanary, err := readOptionalFile(*apiCanaryFile, 4096)
	if err != nil {
		return err
	}
	manager, identity, err := newManager(options)
	if err != nil {
		return err
	}
	defer manager.Close()
	manager.SetHandler(labHandler())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := manager.Start(ctx); err != nil {
		return err
	}
	nodeID, err := identity.NodeID(ctx)
	if err != nil {
		return err
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, options.connectTimeout)
	defer readyCancel()
	if err := waitCoordinator(readyCtx, manager); err != nil {
		return err
	}

	started := time.Now()
	loadCtx, loadCancel := context.WithCancel(ctx)
	if *duration > 0 {
		var durationCancel context.CancelFunc
		loadCtx, durationCancel = context.WithTimeout(loadCtx, *duration)
		defer durationCancel()
	}
	defer loadCancel()
	var pacer <-chan time.Time
	var pacerTicker *time.Ticker
	if *requestRate > 0 {
		interval := time.Duration(float64(time.Second) / *requestRate)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		pacerTicker = time.NewTicker(interval)
		defer pacerTicker.Stop()
		pacer = pacerTicker.C
	}
	var next, succeeded, recovered, failed atomic.Int64
	firstError := make(chan error, 1)
	var workers sync.WaitGroup
	for worker := 0; worker < *concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				index := next.Add(1) - 1
				if *requestCount > 0 && index >= *requestCount {
					return
				}
				if err := loadCtx.Err(); err != nil {
					return
				}
				if pacer != nil {
					select {
					case <-pacer:
					case <-loadCtx.Done():
						return
					}
				}
				if err := performRequest(loadCtx, manager, *target, nodeID, index, *bodyBytes, canary, apiCanary, *gossipEvery); err != nil {
					// Reaching the requested soak duration is a clean stop, even if
					// the deadline interrupts a request that was already in flight.
					if *duration > 0 && loadCtx.Err() != nil &&
						(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
						return
					}
					failureCount := failed.Add(1)
					if failureCount <= *maxFailures {
						log.Printf("tolerated injected-fault request failure %d/%d: %s", failureCount, *maxFailures, err)
						continue
					}
					select {
					case firstError <- err:
					default:
					}
					loadCancel()
					return
				}
				succeeded.Add(1)
				if failed.Load() > 0 {
					recovered.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(started)
	status := manager.Status()
	targetNodeID := targetPeerNodeID(*target)
	result := loadResult{
		NodeID: nodeID, TargetNodeID: targetNodeID, ExpectedPath: *expectedPath,
		RequestsSucceeded: succeeded.Load(), RecoveredRequests: recovered.Load(), RequestsFailed: failed.Load(),
		DurationMS: elapsed.Milliseconds(), Status: status,
	}
	if elapsed > 0 {
		result.RequestsPerSecond = float64(result.RequestsSucceeded) / elapsed.Seconds()
	}
	if err := writeJSON(os.Stdout, result); err != nil {
		return err
	}
	select {
	case err := <-firstError:
		return err
	default:
	}
	if result.RequestsSucceeded == 0 {
		return fmt.Errorf("load completed without a successful request")
	}
	if *expectedPath != "any" {
		path := peerPath(status, targetNodeID)
		if path != *expectedPath {
			return fmt.Errorf("selected path %q, expected %q", path, *expectedPath)
		}
	}
	return nil
}

func newManager(options commonOptions) (*connectice.Manager, *diskIdentity, error) {
	if options.identityFile == "" || options.credentialFile == "" || options.coordinator == "" {
		return nil, nil, fmt.Errorf("identity-file, credential-file, and coordinator are required")
	}
	identity, err := loadIdentity(options.identityFile)
	if err != nil {
		return nil, nil, err
	}
	credential, err := readRequiredFile(options.credentialFile, maxSecretFileBytes)
	if err != nil {
		return nil, nil, err
	}
	hosts := splitCSV(options.iceHosts)
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("ice-server-hosts is required")
	}
	manager, err := connectice.New(identity, connectice.Config{
		Coordinators: []connectice.CoordinatorConfig{{
			URL: options.coordinator, Credential: string(credential), AllowPrivateICEServers: true,
			AllowedICEServerHosts: hosts,
		}},
		AllowTURN: options.allowTURN, GatherTimeout: options.gatherTimeout, ConnectTimeout: options.connectTimeout,
		RequestTimeout: options.requestTimeout, IdleTimeout: options.idleTimeout, MaxPeerConnections: 32,
		AllowedBasePath: options.basePath, MaxBodyBytes: 128 << 20, MaxInflightBytes: 256 << 20,
	})
	if err != nil {
		return nil, nil, err
	}
	return manager, identity, nil
}

func labHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || (request.URL.Path != "/gonzbnet/v1/lab/echo" && request.URL.Path != "/gonzbnet/v1/gossip") {
			http.NotFound(w, request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Lab-SHA256", fmt.Sprintf("%x", sha256.Sum256(body)))
		_, _ = w.Write(body)
	})
}

func performRequest(ctx context.Context, manager *connectice.Manager, target, authorNodeID string, index int64, size int, canary, apiCanary []byte, gossipEvery int64) error {
	path := "/lab/echo"
	if gossipEvery > 0 && index%gossipEvery == 0 {
		path = "/gossip"
	}
	payload := deterministicBody(index, size, canary)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Lab-Request-Id", strconv.FormatInt(index, 10))
	if len(apiCanary) > 0 {
		request.Header.Set("Authorization", fmt.Sprintf(
			`GoNZBNet node_id="%s", timestamp="1970-01-01T00:00:00Z", nonce="%s", signature="%s"`,
			authorNodeID, apiCanary, apiCanary,
		))
	}
	response, err := manager.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("request %d: %w", index, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("request %d response: %w", index, err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(responseBody, payload) {
		return fmt.Errorf(
			"request %d response mismatch: status=%d bytes=%d digest=%x",
			index, response.StatusCode, len(responseBody), sha256.Sum256(responseBody),
		)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(payload))
	if response.Header.Get("X-Lab-Sha256") != wantDigest {
		return fmt.Errorf("request %d response digest mismatch", index)
	}
	return nil
}

func deterministicBody(index int64, size int, canary []byte) []byte {
	payload := make([]byte, size)
	written := copy(payload, canary)
	var block uint64
	for written < len(payload) {
		sum := sha256.Sum256([]byte(fmt.Sprintf("gonzb-connect-lab:%d:%d", index, block)))
		written += copy(payload[written:], sum[:])
		block++
	}
	return payload
}

func waitCoordinator(ctx context.Context, manager *connectice.Manager) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if coordinatorReady(manager.Status()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("coordinator did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func coordinatorReady(status connectice.Status) bool {
	for _, coordinator := range status.Coordinators {
		if coordinator.Reachable {
			return true
		}
	}
	return false
}

func peerPath(status connectice.Status, nodeID string) string {
	for _, peer := range status.Peers {
		if peer.NodeID == nodeID {
			return peer.PathType
		}
	}
	return ""
}

func targetPeerNodeID(locator string) string {
	afterScheme := strings.TrimPrefix(locator, connectice.Scheme+"://")
	userInfo, _, _ := strings.Cut(afterScheme, "@")
	return strings.ToLower(userInfo)
}

func loadOrCreateIdentity(fileName string) (*diskIdentity, bool, error) {
	identity, err := loadIdentity(fileName)
	if err == nil {
		return identity, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(fileName), 0o700); err != nil {
		return nil, false, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(privateKey) + "\n"
	temporary := fileName + ".tmp"
	// #nosec G304 -- this local qualification CLI intentionally writes the
	// identity path explicitly selected by its operator.
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	if _, err = io.WriteString(file, encoded); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, fileName)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return nil, false, err
	}
	return &diskIdentity{privateKey: privateKey}, true, nil
}

func loadIdentity(fileName string) (*diskIdentity, error) {
	// #nosec G304 -- this local qualification CLI intentionally reads the
	// identity path explicitly selected by its operator.
	raw, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1024 {
		return nil, fmt.Errorf("identity file exceeds 1 KiB")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity file contains an invalid Ed25519 key")
	}
	return &diskIdentity{privateKey: ed25519.PrivateKey(decoded)}, nil
}

func readRequiredFile(fileName string, limit int64) ([]byte, error) {
	// #nosec G304 -- this local qualification CLI intentionally reads the
	// secret path explicitly selected by its operator.
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("secret file exceeds %d bytes", limit)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || strings.ContainsAny(string(raw), " \t\r\n") {
		return nil, fmt.Errorf("secret file contains invalid whitespace")
	}
	return raw, nil
}

func readOptionalFile(fileName string, limit int64) ([]byte, error) {
	if strings.TrimSpace(fileName) == "" {
		return nil, nil
	}
	return readRequiredFile(fileName, limit)
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func writeHTTPJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
