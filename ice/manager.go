package ice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectclient "github.com/datallboy/gonzb-connect/client"
	"github.com/datallboy/gonzb-connect/protocol"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

const (
	Scheme                = "gonzb+ice"
	TransportNodeIDHeader = "X-GoNZBNet-Transport-Node-ID"
	frameHeader           = byte(1)
	frameData             = byte(2)
	frameEnd              = byte(3)
	maxHeaderBytes        = 32 << 10
	dataFrameBytes        = 16 << 10
	maxInboundChannels    = 8
	messageQueueDepth     = 16
	maxRemoteCandidates   = 32
	maxSDPBytes           = 96 << 10
	channelAdmissionWait  = 500 * time.Millisecond
	// Pion retains closed DataChannel state for the lifetime of a
	// PeerConnection. Turn over the connection before per-request channels can
	// make a continuously busy peer grow without limit.
	maxOutboundChannelsPerConnection = 256
)

type Identity interface {
	protocol.Signer
}

type CoordinatorConfig struct {
	URL                    string
	Credential             string
	AllowPrivateICEServers bool
	AllowedICEServerHosts  []string
}

type Config struct {
	Coordinators          []CoordinatorConfig
	AllowTURN             bool
	GatherTimeout         time.Duration
	ConnectTimeout        time.Duration
	IdleTimeout           time.Duration
	MaxPeerConnections    int
	AllowedBasePath       string
	MaxBodyBytes          int64
	RequestTimeout        time.Duration
	MaxInboundRequests    int
	MaxInflightBytes      int64
	ChannelsPerMinute     int
	RequestsPerMinute     int
	RemoteIPAllowed       func(net.IP) bool
	LocalInterfaceAllowed func(string) bool
	VerifyPeerKey         func(context.Context, string, ed25519.PublicKey) error
	Observe               func(Observation)
}

type Observation struct {
	Coordinator   string
	PeerNodeID    string
	Reachable     bool
	PathType      string
	ICEState      string
	RTTMS         int64
	Reconnects    int64
	BytesSent     int64
	BytesReceived int64
	Failure       string
}

// Status is a payload-safe point-in-time transport snapshot for health checks,
// lab assertions, and operators. It deliberately omits SDP, candidates,
// credentials, local addresses, and remote addresses.
type Status struct {
	NodeID            string              `json:"node_id"`
	Coordinators      []CoordinatorStatus `json:"coordinators"`
	Peers             []PeerStatus        `json:"peers"`
	InflightBodyBytes int64               `json:"inflight_body_bytes"`
}

type CoordinatorStatus struct {
	URL        string `json:"url"`
	Reachable  bool   `json:"reachable"`
	Reconnects int64  `json:"reconnects"`
}

type PeerStatus struct {
	NodeID        string `json:"node_id"`
	Coordinator   string `json:"coordinator"`
	PathType      string `json:"path_type"`
	Connection    string `json:"connection_state"`
	ICEState      string `json:"ice_state"`
	RTTMS         int64  `json:"rtt_ms"`
	Restarts      int64  `json:"restarts"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
	Active        int32  `json:"active_requests"`
	Inbound       int32  `json:"inbound_requests"`
	Channels      int32  `json:"inbound_channels"`
}

type Manager struct {
	identity Identity
	cfg      Config
	nodeID   string
	api      *webrtc.API

	mu           sync.Mutex
	coordinators map[string]*coordinatorState
	peers        map[string]*peer
	sessions     map[string]*peer
	replay       *protocol.ReplayCache
	handler      http.Handler
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	closed       bool
	inboundSem   chan struct{}
	bodyBudget   *byteBudget
}

type coordinatorState struct {
	config        CoordinatorConfig
	client        *connectclient.Client
	mu            sync.RWMutex
	connected     bool
	turn          connectclient.TURNResponse
	turnFetchedAt time.Time
	reconnects    int64
}

type peer struct {
	manager     *Manager
	nodeID      string
	coordinator *coordinatorState

	mu                sync.Mutex
	pc                *webrtc.PeerConnection
	sessionID         string
	connected         chan struct{}
	done              chan struct{}
	connectOnce       sync.Once
	doneOnce          sync.Once
	err               error
	lastUsed          time.Time
	active            atomic.Int32
	inbound           atomic.Int32
	channels          atomic.Int32
	pathType          string
	negotiating       bool
	established       bool
	gossipMu          sync.Mutex
	gossip            *outboundChannel
	gossipIn          atomic.Bool
	rateMu            sync.Mutex
	rateWindow        time.Time
	rateStarts        int
	requestRateMu     sync.Mutex
	requestRateWindow time.Time
	requestRateStarts int
	restarts          atomic.Int64
	bytesSent         atomic.Int64
	bytesReceived     atomic.Int64
	openedChannels    atomic.Int64
}

type outboundChannel struct {
	channel  *webrtc.DataChannel
	opened   chan struct{}
	messages chan []byte
}

func New(identity Identity, cfg Config) (*Manager, error) {
	if identity == nil {
		return nil, fmt.Errorf("traversal identity is required")
	}
	nodeID, err := identity.NodeID(context.Background())
	if err != nil {
		return nil, err
	}
	if !protocol.ValidNodeID(nodeID) {
		return nil, fmt.Errorf("traversal identity returned an invalid node ID")
	}
	if len(cfg.Coordinators) == 0 || len(cfg.Coordinators) > 3 {
		return nil, fmt.Errorf("one to three traversal coordinators are required")
	}
	if cfg.GatherTimeout <= 0 {
		cfg.GatherTimeout = 10 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.MaxPeerConnections <= 0 {
		cfg.MaxPeerConnections = 32
	}
	if cfg.MaxPeerConnections > 256 {
		return nil, fmt.Errorf("traversal peer connection limit exceeds 256")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 16 << 20
	}
	if cfg.MaxBodyBytes > 128<<20 {
		return nil, fmt.Errorf("traversal body limit exceeds 128 MiB")
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.RequestTimeout > 5*time.Minute {
		return nil, fmt.Errorf("traversal request timeout exceeds five minutes")
	}
	if cfg.MaxInboundRequests <= 0 {
		cfg.MaxInboundRequests = 64
	}
	if cfg.MaxInboundRequests > 1024 {
		return nil, fmt.Errorf("traversal inbound request limit exceeds 1024")
	}
	if cfg.MaxInflightBytes <= 0 {
		cfg.MaxInflightBytes = 64 << 20
		if 2*cfg.MaxBodyBytes > cfg.MaxInflightBytes {
			cfg.MaxInflightBytes = 2 * cfg.MaxBodyBytes
		}
	}
	if cfg.MaxInflightBytes < cfg.MaxBodyBytes || cfg.MaxInflightBytes > 512<<20 {
		return nil, fmt.Errorf("traversal in-flight byte budget must be between the body limit and 512 MiB")
	}
	if cfg.ChannelsPerMinute <= 0 {
		cfg.ChannelsPerMinute = 120
	}
	if cfg.ChannelsPerMinute > 600 {
		return nil, fmt.Errorf("traversal channel rate exceeds 600 per minute")
	}
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = 240
	}
	if cfg.RequestsPerMinute > 1200 {
		return nil, fmt.Errorf("traversal request rate exceeds 1200 per minute")
	}
	cfg.AllowedBasePath = strings.TrimRight(strings.TrimSpace(cfg.AllowedBasePath), "/")
	if cfg.AllowedBasePath == "" {
		cfg.AllowedBasePath = "/gonzbnet/v1"
	}
	if cfg.AllowedBasePath == "/" || !safePath(cfg.AllowedBasePath) {
		return nil, fmt.Errorf("invalid traversal federation base path")
	}
	m := &Manager{
		identity: identity, cfg: cfg, nodeID: nodeID,
		coordinators: make(map[string]*coordinatorState), peers: make(map[string]*peer),
		sessions: make(map[string]*peer), replay: protocol.NewReplayCache(), api: newWebRTCAPI(cfg.RemoteIPAllowed, cfg.LocalInterfaceAllowed),
		inboundSem: make(chan struct{}, cfg.MaxInboundRequests), bodyBudget: &byteBudget{limit: cfg.MaxInflightBytes},
	}
	for _, item := range cfg.Coordinators {
		parsed, err := url.Parse(strings.TrimSpace(item.URL))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(item.Credential) == "" {
			return nil, fmt.Errorf("invalid traversal coordinator configuration")
		}
		host := strings.ToLower(parsed.Host)
		if _, exists := m.coordinators[host]; exists {
			return nil, fmt.Errorf("duplicate traversal coordinator %q", host)
		}
		if len(item.AllowedICEServerHosts) == 0 || len(item.AllowedICEServerHosts) > 4 {
			return nil, fmt.Errorf("traversal coordinator requires one to four allowed ICE server hosts")
		}
		allowedHosts := make([]string, 0, len(item.AllowedICEServerHosts))
		seenHosts := make(map[string]struct{}, len(item.AllowedICEServerHosts))
		for _, allowedHost := range item.AllowedICEServerHosts {
			allowedHost = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(allowedHost), "[]")), ".")
			if !validServerHost(allowedHost) {
				return nil, fmt.Errorf("invalid allowed ICE server host")
			}
			if _, duplicate := seenHosts[allowedHost]; duplicate {
				return nil, fmt.Errorf("duplicate allowed ICE server host")
			}
			seenHosts[allowedHost] = struct{}{}
			allowedHosts = append(allowedHosts, allowedHost)
		}
		state := &coordinatorState{config: item}
		state.client = connectclient.New(item.URL, item.Credential, identity)
		state.client.SetAllowPrivateICEServers(item.AllowPrivateICEServers)
		state.client.SetAllowedICEServerHosts(allowedHosts)
		m.coordinators[host] = state
	}
	return m, nil
}

func validServerHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func newWebRTCAPI(allowedIP func(net.IP) bool, allowedInterface func(string) bool) *webrtc.API {
	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetSCTPMaxMessageSize(uint32(maxHeaderBytes + 1))
	settingEngine.SetSCTPMaxReceiveBufferSize(1 << 20)
	settingEngine.SetICEMaxBindingRequests(7)
	settingEngine.SetInterfaceFilter(func(name string) bool {
		if !safeLocalInterface(name) {
			return false
		}
		return allowedInterface == nil || allowedInterface(name)
	})
	settingEngine.SetRemoteIPFilter(func(ip net.IP) bool {
		if !safeRemoteIP(ip) {
			return false
		}
		return allowedIP == nil || allowedIP(ip)
	})
	return webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))
}

func safeLocalInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "podman"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return name != "" && name != "lo"
}

func safeRemoteIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func validInboundFrameSize(frame []byte) bool {
	return len(frame) > 0 && len(frame) <= maxHeaderBytes+1
}

func waitForGathering(ctx context.Context, complete <-chan struct{}, timeout time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-complete:
		return nil
	case <-timer.C:
		return fmt.Errorf("ICE candidate gathering timed out before completion")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validateRemoteSDP(payload string) error {
	if len(payload) == 0 || len(payload) > maxSDPBytes {
		return fmt.Errorf("remote SDP exceeds bounds")
	}
	description := &sdp.SessionDescription{}
	if err := description.UnmarshalString(payload); err != nil {
		return fmt.Errorf("parse remote SDP: %w", err)
	}
	if len(description.MediaDescriptions) != 1 {
		return fmt.Errorf("remote SDP must contain exactly one media section")
	}
	media := description.MediaDescriptions[0]
	if !strings.EqualFold(media.MediaName.Media, "application") {
		return fmt.Errorf("remote SDP contains unsupported media")
	}
	proto := strings.ToUpper(strings.Join(media.MediaName.Protos, "/"))
	if proto != "UDP/DTLS/SCTP" && proto != "DTLS/SCTP" {
		return fmt.Errorf("remote SDP contains unsupported data transport")
	}
	foundDataChannel := false
	for _, format := range media.MediaName.Formats {
		if strings.EqualFold(format, "webrtc-datachannel") {
			foundDataChannel = true
			break
		}
	}
	if !foundDataChannel {
		return fmt.Errorf("remote SDP omits the WebRTC DataChannel format")
	}

	attributes := append([]sdp.Attribute(nil), description.Attributes...)
	attributes = append(attributes, media.Attributes...)
	candidates := make(map[string]struct{})
	candidateComponents := make(map[string]int)
	fingerprints := 0
	iceUfrags := 0
	icePasswords := 0
	for _, attribute := range attributes {
		switch attribute.Key {
		case sdp.AttrKeyCandidate:
			if _, duplicate := candidates[attribute.Value]; duplicate {
				return fmt.Errorf("remote SDP contains a duplicate ICE candidate")
			}
			candidates[attribute.Value] = struct{}{}
			if len(candidates) > maxRemoteCandidates {
				return fmt.Errorf("remote SDP exceeds the ICE candidate limit (%d > %d)", len(candidates), maxRemoteCandidates)
			}
			fields := strings.Fields(attribute.Value)
			if len(fields) < 8 || (fields[1] != "1" && fields[1] != "2") ||
				(!strings.EqualFold(fields[2], "udp") && !strings.EqualFold(fields[2], "tcp")) || fields[6] != "typ" || !validCandidateType(fields[7]) {
				return fmt.Errorf("remote SDP contains a malformed ICE candidate")
			}
			priority, priorityErr := strconv.ParseUint(fields[3], 10, 32)
			port, portErr := strconv.Atoi(fields[5])
			ip := net.ParseIP(fields[4])
			if priorityErr != nil || priority == 0 || portErr != nil || port < 1 || port > 65535 || ip == nil {
				return fmt.Errorf("remote SDP contains an invalid ICE candidate address")
			}
			candidateComponents[fields[1]]++
			if candidateComponents[fields[1]] > maxRemoteCandidates/2 {
				return fmt.Errorf("remote SDP exceeds the ICE checklist limit")
			}
			if !safeRemoteIP(ip) {
				return fmt.Errorf("remote SDP contains a prohibited ICE candidate address")
			}
		case sdp.AttrKeyICELite:
			return fmt.Errorf("remote SDP must use full ICE")
		case "fingerprint":
			fingerprints++
			fields := strings.Fields(attribute.Value)
			if len(fields) != 2 || !strings.EqualFold(fields[0], "sha-256") || !validSHA256Fingerprint(fields[1]) {
				return fmt.Errorf("remote SDP contains an invalid DTLS fingerprint")
			}
		case "ice-ufrag":
			iceUfrags++
		case "ice-pwd":
			icePasswords++
		}
	}
	if fingerprints != 1 {
		return fmt.Errorf("remote SDP must contain exactly one DTLS fingerprint")
	}
	if iceUfrags != 1 || icePasswords != 1 {
		return fmt.Errorf("remote SDP must contain exactly one ICE credential pair")
	}
	return nil
}

func validCandidateType(value string) bool {
	switch strings.ToLower(value) {
	case "host", "srflx", "prflx", "relay":
		return true
	default:
		return false
	}
}

func validSHA256Fingerprint(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 32 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 || !strings.Contains("0123456789abcdefABCDEF", part[:1]) || !strings.Contains("0123456789abcdefABCDEF", part[1:]) {
			return false
		}
	}
	return true
}

func (m *Manager) SetHandler(handler http.Handler) {
	m.mu.Lock()
	m.handler = handler
	m.mu.Unlock()
}

// CoordinatorStatus returns payload-safe operational metadata. It never
// includes credentials, SDP, candidates, or observed IP addresses.
func (m *Manager) CoordinatorStatus() []map[string]any {
	m.mu.Lock()
	states := make([]*coordinatorState, 0, len(m.coordinators))
	for _, state := range m.coordinators {
		states = append(states, state)
	}
	m.mu.Unlock()
	items := make([]map[string]any, 0, len(states))
	for _, state := range states {
		state.mu.RLock()
		items = append(items, map[string]any{"url": state.config.URL, "reachable": state.connected, "reconnects": state.reconnects})
		state.mu.RUnlock()
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["url"].(string) < items[j]["url"].(string) })
	return items
}

// Status returns bounded operational state without exposing candidate or
// credential material.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	m.mu.Lock()
	states := make([]*coordinatorState, 0, len(m.coordinators))
	for _, state := range m.coordinators {
		states = append(states, state)
	}
	peers := make([]*peer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	nodeID := m.nodeID
	m.mu.Unlock()

	out := Status{NodeID: nodeID, Coordinators: make([]CoordinatorStatus, 0, len(states)), Peers: make([]PeerStatus, 0, len(peers))}
	if m.bodyBudget != nil {
		out.InflightBodyBytes = max(m.bodyBudget.used.Load(), 0)
	}
	for _, state := range states {
		state.mu.RLock()
		out.Coordinators = append(out.Coordinators, CoordinatorStatus{URL: state.config.URL, Reachable: state.connected, Reconnects: state.reconnects})
		state.mu.RUnlock()
	}
	for _, p := range peers {
		p.mu.Lock()
		pc := p.pc
		item := PeerStatus{
			NodeID: p.nodeID, Coordinator: p.coordinator.config.URL, PathType: p.pathType,
			Restarts: p.restarts.Load(), BytesSent: p.bytesSent.Load(), BytesReceived: p.bytesReceived.Load(),
			Active: p.active.Load(), Inbound: p.inbound.Load(), Channels: p.channels.Load(),
		}
		p.mu.Unlock()
		if pc != nil {
			item.Connection = pc.ConnectionState().String()
			item.ICEState = pc.ICEConnectionState().String()
			item.RTTMS = selectedRTTMS(pc)
		}
		out.Peers = append(out.Peers, item)
	}
	sort.Slice(out.Coordinators, func(i, j int) bool { return out.Coordinators[i].URL < out.Coordinators[j].URL })
	sort.Slice(out.Peers, func(i, j int) bool { return out.Peers[i].NodeID < out.Peers[j].NodeID })
	return out
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fmt.Errorf("traversal manager is closed")
	}
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.started = true
	states := make([]*coordinatorState, 0, len(m.coordinators))
	for _, state := range m.coordinators {
		states = append(states, state)
	}
	m.mu.Unlock()
	for _, state := range states {
		go m.runCoordinator(state)
	}
	go m.reapIdlePeers()
	return nil
}

func (m *Manager) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != Scheme {
		return nil, fmt.Errorf("traversal transport requires a gonzb+ice URL")
	}
	if err := m.ensureStarted(); err != nil {
		return nil, err
	}
	targetNodeID, coordinator, err := m.resolveTarget(request.URL)
	if err != nil {
		return nil, err
	}
	connectCtx, cancel := context.WithTimeout(request.Context(), m.cfg.ConnectTimeout)
	defer cancel()
	p, err := m.ensurePeer(connectCtx, targetNodeID, coordinator)
	if err != nil {
		return nil, err
	}
	defer p.active.Add(-1)
	pc, err := waitForActivePeerConnection(connectCtx, p)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.lastUsed = time.Now().UTC()
	p.mu.Unlock()
	exchangeCtx, exchangeCancel := context.WithTimeout(request.Context(), m.cfg.RequestTimeout)
	defer exchangeCancel()
	if strings.HasSuffix(strings.TrimRight(request.URL.Path, "/"), "/gossip") {
		return m.roundTripGossip(connectCtx, exchangeCtx, p, pc, request)
	}
	channel, err := pc.CreateDataChannel("http:"+randomID(), nil)
	if err != nil {
		return nil, err
	}
	p.openedChannels.Add(1)
	defer channel.Close()
	opened := make(chan struct{})
	openOnce := sync.Once{}
	messages := make(chan []byte, messageQueueDepth)
	channel.OnOpen(func() { openOnce.Do(func() { close(opened) }) })
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if !validInboundFrameSize(message.Data) {
			_ = channel.Close()
			return
		}
		copyBytes := append([]byte(nil), message.Data...)
		select {
		case messages <- copyBytes:
		case <-exchangeCtx.Done():
		}
	})
	channel.OnClose(func() {
		openOnce.Do(func() { close(opened) })
		go func() {
			select {
			case messages <- nil:
			case <-exchangeCtx.Done():
			}
		}()
	})
	select {
	case <-opened:
	case <-connectCtx.Done():
		return nil, fmt.Errorf("open traversal data channel: %w", connectCtx.Err())
	}
	return m.exchange(exchangeCtx, p, channel, messages, request)
}

func (m *Manager) exchange(ctx context.Context, p *peer, channel *webrtc.DataChannel, messages <-chan []byte, request *http.Request) (*http.Response, error) {
	body, err := readLimitedWithBudget(request.Body, m.cfg.MaxBodyBytes, m.bodyBudget)
	if err != nil {
		return nil, err
	}
	defer m.bodyBudget.release(int64(len(body)))
	header := requestHeader{Method: request.Method, Path: request.URL.Path, RawQuery: request.URL.RawQuery, Header: request.Header.Clone()}
	bytesSent, err := sendMessage(ctx, channel, header, body)
	p.bytesSent.Add(bytesSent)
	if err != nil {
		return nil, err
	}
	var responseHeader responseHeader
	responseBody, bytesReceived, err := receiveMessageWithBudget(ctx, messages, &responseHeader, m.cfg.MaxBodyBytes, m.bodyBudget)
	p.bytesReceived.Add(bytesReceived)
	if err != nil {
		m.observe(p, bytesSent, bytesReceived, err)
		return nil, err
	}
	if responseHeader.StatusCode < 100 || responseHeader.StatusCode > 599 {
		m.bodyBudget.release(int64(len(responseBody)))
		return nil, fmt.Errorf("traversal response contains an invalid HTTP status")
	}
	if err := validateHTTPHeader(responseHeader.Header); err != nil {
		m.bodyBudget.release(int64(len(responseBody)))
		return nil, err
	}
	m.observe(p, bytesSent, bytesReceived, nil)
	return &http.Response{
		StatusCode:    responseHeader.StatusCode,
		Status:        fmt.Sprintf("%d %s", responseHeader.StatusCode, http.StatusText(responseHeader.StatusCode)),
		Header:        responseHeader.Header,
		Body:          newBudgetedReadCloser(responseBody, m.bodyBudget),
		ContentLength: int64(len(responseBody)),
		Request:       request,
	}, nil
}

func (m *Manager) roundTripGossip(connectCtx, requestCtx context.Context, p *peer, pc *webrtc.PeerConnection, request *http.Request) (*http.Response, error) {
	p.gossipMu.Lock()
	defer p.gossipMu.Unlock()
	state := p.gossip
	if state == nil || state.channel == nil || state.channel.ReadyState() == webrtc.DataChannelStateClosed {
		channel, err := pc.CreateDataChannel("gossip:"+m.nodeID, nil)
		if err != nil {
			return nil, err
		}
		state = &outboundChannel{channel: channel, opened: make(chan struct{}), messages: make(chan []byte, messageQueueDepth)}
		openOnce := sync.Once{}
		channel.OnOpen(func() { openOnce.Do(func() { close(state.opened) }) })
		channel.OnMessage(func(message webrtc.DataChannelMessage) {
			if !validInboundFrameSize(message.Data) {
				_ = channel.Close()
				return
			}
			payload := append([]byte(nil), message.Data...)
			select {
			case state.messages <- payload:
			case <-m.ctx.Done():
			case <-p.done:
			}
		})
		channel.OnClose(func() {
			openOnce.Do(func() { close(state.opened) })
			go func() {
				select {
				case state.messages <- nil:
				case <-m.ctx.Done():
				case <-p.done:
				}
			}()
		})
		p.gossip = state
	}
	if state.channel.ReadyState() != webrtc.DataChannelStateOpen {
		select {
		case <-state.opened:
		case <-connectCtx.Done():
			_ = state.channel.Close()
			p.gossip = nil
			return nil, fmt.Errorf("open traversal gossip channel: %w", connectCtx.Err())
		}
	}
	response, err := m.exchange(requestCtx, p, state.channel, state.messages, request)
	if err != nil {
		_ = state.channel.Close()
		p.gossip = nil
	}
	return response, err
}

func (m *Manager) ensureStarted() error {
	m.mu.Lock()
	started, closed := m.started, m.closed
	m.mu.Unlock()
	if closed {
		return fmt.Errorf("traversal manager is closed")
	}
	if !started {
		return m.Start(context.Background())
	}
	return nil
}

func (m *Manager) resolveTarget(locator *url.URL) (string, *coordinatorState, error) {
	if locator.User == nil || locator.User.Username() == "" {
		return "", nil, fmt.Errorf("traversal locator requires a target node ID")
	}
	if _, password := locator.User.Password(); password {
		return "", nil, fmt.Errorf("traversal locator must not contain a password")
	}
	nodeID := strings.ToLower(locator.User.Username())
	if !protocol.ValidNodeID(nodeID) {
		return "", nil, fmt.Errorf("traversal locator contains an invalid target node ID")
	}
	host := strings.ToLower(locator.Host)
	m.mu.Lock()
	state := m.coordinators[host]
	m.mu.Unlock()
	if state == nil {
		return "", nil, fmt.Errorf("target does not share a configured traversal coordinator")
	}
	if nodeID == m.nodeID {
		return "", nil, fmt.Errorf("cannot create traversal connection to the local node")
	}
	return nodeID, state, nil
}

func (m *Manager) ensurePeer(ctx context.Context, nodeID string, coordinator *coordinatorState) (*peer, error) {
	for {
		m.mu.Lock()
		if existing := m.peers[nodeID]; existing != nil {
			if existing.openedChannels.Load() >= maxOutboundChannelsPerConnection {
				if existing.active.Load() == 0 && existing.inbound.Load() == 0 {
					delete(m.peers, nodeID)
					m.mu.Unlock()
					m.closePeer(existing, fmt.Errorf("traversal peer connection reached channel turnover limit"), false)
					continue
				}
				m.mu.Unlock()
				select {
				case <-time.After(10 * time.Millisecond):
					continue
				case <-ctx.Done():
					return nil, fmt.Errorf("wait for traversal peer connection turnover: %w", ctx.Err())
				}
			}
			existing.active.Add(1)
			m.mu.Unlock()
			result, err := waitForPeer(ctx, existing)
			if err != nil {
				existing.active.Add(-1)
			}
			return result, err
		}
		if len(m.peers) >= m.cfg.MaxPeerConnections && !m.evictOldestIdleLocked() {
			m.mu.Unlock()
			return nil, fmt.Errorf("traversal peer connection pool is full")
		}
		p := &peer{manager: m, nodeID: nodeID, coordinator: coordinator, connected: make(chan struct{}), done: make(chan struct{}), lastUsed: time.Now().UTC()}
		p.active.Store(1)
		m.peers[nodeID] = p
		m.mu.Unlock()
		if m.nodeID < nodeID {
			go m.createOffer(p)
		} else {
			p.mu.Lock()
			p.negotiating = true
			p.mu.Unlock()
			envelope, err := protocol.NewEnvelope(ctx, m.identity, protocol.MessageConnect, randomID(), nodeID, "", time.Now().UTC(), 2*time.Minute)
			if err != nil {
				m.failPeer(p, err)
			} else if err := m.send(coordinator, envelope); err != nil {
				m.failPeer(p, err)
			} else {
				go m.watchNegotiation(p, nil, "")
			}
		}
		result, err := waitForPeer(ctx, p)
		if err != nil {
			p.active.Add(-1)
		}
		return result, err
	}
}

func waitForPeer(ctx context.Context, p *peer) (*peer, error) {
	select {
	case <-p.connected:
		return p, nil
	case <-p.done:
		p.mu.Lock()
		err := p.err
		p.mu.Unlock()
		if err == nil {
			err = fmt.Errorf("traversal peer connection closed")
		}
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("connect traversal peer: %w", ctx.Err())
	}
}

func waitForActivePeerConnection(ctx context.Context, p *peer) (*webrtc.PeerConnection, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		pc := p.pc
		err := p.err
		negotiating := p.negotiating
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if pc != nil && !negotiating && pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
			return pc, nil
		}
		select {
		case <-p.done:
			return nil, fmt.Errorf("traversal peer connection closed")
		case <-ctx.Done():
			return nil, fmt.Errorf("connect traversal peer: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (m *Manager) createOffer(p *peer) {
	p.mu.Lock()
	if p.pc != nil || p.negotiating {
		p.mu.Unlock()
		return
	}
	p.negotiating = true
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(m.ctx, m.cfg.ConnectTimeout)
	defer cancel()
	if err := m.waitCoordinatorReady(ctx, p.coordinator); err != nil {
		m.failPeer(p, err)
		return
	}
	sessionID := randomID()
	pc, err := m.newPeerConnection(p, sessionID)
	if err != nil {
		m.failPeer(p, err)
		return
	}
	// Creating a DataChannel before the initial offer causes WebRTC to include
	// the SCTP application section. Ordinary request and gossip channels can
	// then be opened after ICE/DTLS connectivity is established.
	control, err := pc.CreateDataChannel("control/1", nil)
	if err != nil {
		m.failPeer(p, err)
		return
	}
	control.OnOpen(func() { _ = control.Close() })
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		m.failPeer(p, err)
		return
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		m.failPeer(p, err)
		return
	}
	if err := waitForGathering(ctx, gatherComplete, m.cfg.GatherTimeout); err != nil {
		m.failPeer(p, err)
		return
	}
	local := pc.LocalDescription()
	if local == nil {
		m.failPeer(p, fmt.Errorf("local traversal offer is unavailable"))
		return
	}
	if err := validateRemoteSDP(local.SDP); err != nil {
		m.failPeer(p, fmt.Errorf("local SDP policy: %w", err))
		return
	}
	envelope, err := protocol.NewEnvelope(ctx, m.identity, protocol.MessageOffer, sessionID, p.nodeID, local.SDP, time.Now().UTC(), 2*time.Minute)
	if err != nil {
		m.failPeer(p, err)
		return
	}
	if err := m.send(p.coordinator, envelope); err != nil {
		m.failPeer(p, err)
		return
	}
	go m.watchNegotiation(p, pc, sessionID)
}

func (m *Manager) waitCoordinatorReady(ctx context.Context, state *coordinatorState) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state.mu.RLock()
		ready := state.connected && !state.turnFetchedAt.IsZero()
		state.mu.RUnlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("traversal coordinator readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (m *Manager) acceptOffer(state *coordinatorState, envelope protocol.Envelope) error {
	if envelope.SourceNodeID >= m.nodeID {
		return fmt.Errorf("offer violates deterministic offerer ordering")
	}
	m.mu.Lock()
	p := m.peers[envelope.SourceNodeID]
	if p == nil {
		if len(m.peers) >= m.cfg.MaxPeerConnections && !m.evictOldestIdleLocked() {
			m.mu.Unlock()
			return fmt.Errorf("traversal peer connection pool is full")
		}
		p = &peer{manager: m, nodeID: envelope.SourceNodeID, coordinator: state, connected: make(chan struct{}), done: make(chan struct{}), lastUsed: time.Now().UTC()}
		m.peers[p.nodeID] = p
	}
	m.mu.Unlock()
	p.mu.Lock()
	pc := p.pc
	established := p.established
	p.negotiating = true
	p.mu.Unlock()
	if pc == nil || !established {
		var err error
		pc, err = m.newPeerConnection(p, envelope.SessionID)
		if err != nil {
			m.failPeer(p, err)
			return err
		}
	} else {
		if err := pc.SetConfiguration(m.peerConfiguration(p.coordinator)); err != nil {
			m.failPeer(p, err)
			return err
		}
		m.registerSession(p, envelope.SessionID)
	}
	if err := validateRemoteSDP(envelope.Payload); err != nil {
		m.failPeer(p, err)
		return err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: envelope.Payload}); err != nil {
		m.failPeer(p, err)
		return err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		m.failPeer(p, err)
		return err
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		m.failPeer(p, err)
		return err
	}
	if err := waitForGathering(m.ctx, gatherComplete, m.cfg.GatherTimeout); err != nil {
		m.failPeer(p, err)
		return err
	}
	local := pc.LocalDescription()
	if local == nil {
		err := fmt.Errorf("local traversal answer is unavailable")
		m.failPeer(p, err)
		return err
	}
	if err := validateRemoteSDP(local.SDP); err != nil {
		err = fmt.Errorf("local SDP policy: %w", err)
		m.failPeer(p, err)
		return err
	}
	response, err := protocol.NewEnvelope(m.ctx, m.identity, protocol.MessageAnswer, envelope.SessionID, envelope.SourceNodeID, local.SDP, time.Now().UTC(), 2*time.Minute)
	if err != nil {
		m.failPeer(p, err)
		return err
	}
	if err := m.send(state, response); err != nil {
		m.failPeer(p, err)
		return err
	}
	go m.watchNegotiation(p, pc, envelope.SessionID)
	return nil
}

func (m *Manager) acceptAnswer(envelope protocol.Envelope) error {
	m.mu.Lock()
	p := m.sessions[envelope.SessionID]
	m.mu.Unlock()
	if p == nil || p.nodeID != envelope.SourceNodeID {
		return fmt.Errorf("answer does not match an active negotiation")
	}
	p.mu.Lock()
	pc := p.pc
	p.mu.Unlock()
	if pc == nil {
		return fmt.Errorf("answer peer connection is unavailable")
	}
	if err := validateRemoteSDP(envelope.Payload); err != nil {
		m.failPeer(p, err)
		return err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: envelope.Payload}); err != nil {
		m.failPeer(p, err)
		return err
	}
	return nil
}

func (m *Manager) newPeerConnection(p *peer, sessionID string) (*webrtc.PeerConnection, error) {
	api := m.api
	if api == nil {
		api = newWebRTCAPI(m.cfg.RemoteIPAllowed, m.cfg.LocalInterfaceAllowed)
	}
	pc, err := api.NewPeerConnection(m.peerConfiguration(p.coordinator))
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	old := p.pc
	p.pc = pc
	p.negotiating = true
	p.established = false
	p.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	m.registerSession(p, sessionID)
	pc.OnDataChannel(func(channel *webrtc.DataChannel) {
		if len(channel.Label()) > 128 {
			_ = channel.Close()
			return
		}
		switch {
		case channel.Label() == "control/1":
			channel.OnOpen(func() { _ = channel.Close() })
		case strings.HasPrefix(channel.Label(), "http:"):
			m.handleInboundChannel(p, channel, false)
		case strings.HasPrefix(channel.Label(), "gossip:"):
			m.handleInboundChannel(p, channel, true)
		default:
			_ = channel.Close()
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		p.mu.Lock()
		current := p.pc == pc
		p.mu.Unlock()
		if !current {
			return
		}
		switch state {
		case webrtc.PeerConnectionStateConnected:
			p.mu.Lock()
			p.pathType = selectedPathType(pc)
			p.lastUsed = time.Now().UTC()
			p.negotiating = false
			p.established = true
			p.mu.Unlock()
			p.connectOnce.Do(func() { close(p.connected) })
			m.observe(p, 0, 0, nil)
		case webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateFailed:
			go m.recoverPeer(p, pc, state == webrtc.PeerConnectionStateDisconnected)
		case webrtc.PeerConnectionStateClosed:
			m.failPeer(p, fmt.Errorf("ICE connection state %s", state.String()))
		}
	})
	return pc, nil
}

func (m *Manager) peerConfiguration(state *coordinatorState) webrtc.Configuration {
	configuration := webrtc.Configuration{}
	m.refreshTURN(state)
	state.mu.RLock()
	turn := state.turn
	state.mu.RUnlock()
	if len(turn.STUNURIs) > 0 {
		configuration.ICEServers = append(configuration.ICEServers, webrtc.ICEServer{URLs: append([]string(nil), turn.STUNURIs...)})
	}
	if m.cfg.AllowTURN && len(turn.URIs) > 0 {
		configuration.ICEServers = append(configuration.ICEServers, webrtc.ICEServer{URLs: append([]string(nil), turn.URIs...), Username: turn.Username, Credential: turn.Credential})
	}
	return configuration
}

func (m *Manager) recoverPeer(p *peer, pc *webrtc.PeerConnection, waitForTransient bool) {
	if waitForTransient && !waitContext(m.ctx, time.Second) {
		return
	}
	p.mu.Lock()
	if p.pc != pc || !p.established || p.negotiating || pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
		p.mu.Unlock()
		return
	}
	p.negotiating = true
	p.mu.Unlock()
	if m.nodeID < p.nodeID {
		m.restartICE(p, pc)
		return
	}
	envelope, err := protocol.NewEnvelope(m.ctx, m.identity, protocol.MessageConnect, randomID(), p.nodeID, "", time.Now().UTC(), 2*time.Minute)
	if err == nil {
		err = m.send(p.coordinator, envelope)
	}
	if err != nil {
		m.failPeer(p, err)
		return
	}
	go m.watchNegotiation(p, pc, "")
}

func (m *Manager) restartICE(p *peer, pc *webrtc.PeerConnection) {
	ctx, cancel := context.WithTimeout(m.ctx, m.cfg.ConnectTimeout)
	defer cancel()
	p.mu.Lock()
	if p.pc != pc || !p.established {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.restarts.Add(1)
	if err := pc.SetConfiguration(m.peerConfiguration(p.coordinator)); err != nil {
		m.failPeer(p, err)
		return
	}
	sessionID := randomID()
	offer, err := pc.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
	if err != nil {
		m.failPeer(p, err)
		return
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		m.failPeer(p, err)
		return
	}
	if err := waitForGathering(ctx, gatherComplete, m.cfg.GatherTimeout); err != nil {
		m.failPeer(p, err)
		return
	}
	local := pc.LocalDescription()
	if local == nil {
		m.failPeer(p, fmt.Errorf("local ICE restart offer is unavailable"))
		return
	}
	if err := validateRemoteSDP(local.SDP); err != nil {
		m.failPeer(p, fmt.Errorf("local SDP policy: %w", err))
		return
	}
	m.registerSession(p, sessionID)
	envelope, err := protocol.NewEnvelope(ctx, m.identity, protocol.MessageOffer, sessionID, p.nodeID, local.SDP, time.Now().UTC(), 2*time.Minute)
	if err == nil {
		err = m.send(p.coordinator, envelope)
	}
	if err != nil {
		m.failPeer(p, err)
		return
	}
	go m.watchNegotiation(p, pc, sessionID)
}

func (m *Manager) registerSession(p *peer, sessionID string) {
	p.mu.Lock()
	previous := p.sessionID
	p.sessionID = sessionID
	p.mu.Unlock()
	m.mu.Lock()
	if previous != "" && m.sessions[previous] == p {
		delete(m.sessions, previous)
	}
	m.sessions[sessionID] = p
	m.mu.Unlock()
}

func (m *Manager) watchNegotiation(p *peer, pc *webrtc.PeerConnection, sessionID string) {
	if !waitContext(m.ctx, m.cfg.ConnectTimeout) {
		return
	}
	p.mu.Lock()
	timedOut := p.pc == pc && p.negotiating && (sessionID == "" || p.sessionID == sessionID)
	p.mu.Unlock()
	if timedOut {
		m.failPeer(p, fmt.Errorf("ICE negotiation timed out"))
	}
}

func (m *Manager) refreshTURN(state *coordinatorState) {
	state.mu.RLock()
	turn := state.turn
	fetchedAt := state.turnFetchedAt
	connected := state.connected
	state.mu.RUnlock()
	refreshAfter := time.Duration(turn.TTLSeconds) * time.Second / 2
	if refreshAfter <= 0 {
		refreshAfter = 5 * time.Minute
	}
	if !connected || time.Since(fetchedAt) < refreshAfter {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()
	updated, err := state.client.FetchTURNCredentials(ctx)
	if err != nil {
		return
	}
	state.mu.Lock()
	state.turn = updated
	state.turnFetchedAt = time.Now().UTC()
	state.mu.Unlock()
}

func (m *Manager) handleInboundChannel(p *peer, channel *webrtc.DataChannel, persistent bool) {
	messages := make(chan []byte, messageQueueDepth)
	channelCtx, channelCancel := context.WithCancel(m.ctx)
	channel.OnClose(channelCancel)
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		p.mu.Lock()
		p.lastUsed = time.Now().UTC()
		p.mu.Unlock()
		if !validInboundFrameSize(message.Data) {
			_ = channel.Close()
			return
		}
		copyBytes := append([]byte(nil), message.Data...)
		select {
		case messages <- copyBytes:
		case <-channelCtx.Done():
		}
	})
	channel.OnOpen(func() {
		if !p.allowChannel(time.Now().UTC(), m.cfg.ChannelsPerMinute) {
			_ = channel.Close()
			return
		}
		if !p.acquireChannel(channelCtx, maxInboundChannels, channelAdmissionWait) {
			_ = channel.Close()
			return
		}
		if persistent && !p.gossipIn.CompareAndSwap(false, true) {
			p.channels.Add(-1)
			_ = channel.Close()
			return
		}
		go func() {
			defer p.channels.Add(-1)
			if persistent {
				defer p.gossipIn.Store(false)
			} else {
				defer channel.Close()
			}
			ctx := channelCtx
			if !persistent {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, m.cfg.RequestTimeout)
				defer timeoutCancel()
			}
			for {
				if err := m.serveInboundMessage(ctx, p, channel, messages); err != nil || !persistent {
					return
				}
			}
		}()
	})
}

func (p *peer) acquireChannel(ctx context.Context, limit int32, wait time.Duration) bool {
	if p == nil || limit <= 0 {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if wait <= 0 {
		wait = channelAdmissionWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		current := p.channels.Load()
		if current < limit && p.channels.CompareAndSwap(current, current+1) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
}

func (m *Manager) serveInboundMessage(ctx context.Context, p *peer, channel *webrtc.DataChannel, messages <-chan []byte) error {
	var requestHeader requestHeader
	body, _, err := receiveMessageWithBudget(ctx, messages, &requestHeader, m.cfg.MaxBodyBytes, m.bodyBudget)
	if err != nil {
		_ = sendError(ctx, channel, http.StatusBadRequest, err)
		return err
	}
	defer m.bodyBudget.release(int64(len(body)))
	if !p.allowRequest(time.Now().UTC(), m.cfg.RequestsPerMinute) {
		err = fmt.Errorf("traversal request rate exceeded")
		_ = sendError(ctx, channel, http.StatusTooManyRequests, err)
		return err
	}
	if m.inboundSem != nil {
		select {
		case m.inboundSem <- struct{}{}:
			defer func() { <-m.inboundSem }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.inbound.Add(1)
	defer p.inbound.Add(-1)
	if requestHeader.Method != http.MethodGet && requestHeader.Method != http.MethodPost {
		err = fmt.Errorf("traversal HTTP method is not allowed")
		_ = sendError(ctx, channel, http.StatusMethodNotAllowed, err)
		return err
	}
	if err = validateHTTPHeader(requestHeader.Header); err != nil {
		_ = sendError(ctx, channel, http.StatusBadRequest, err)
		return err
	}
	if !m.pathAllowed(requestHeader.Path) {
		err = fmt.Errorf("traversal route is not allowed")
		_ = sendError(ctx, channel, http.StatusForbidden, err)
		return err
	}
	if err = transportIdentityMatches(p.nodeID, requestHeader.Header); err != nil {
		_ = sendError(ctx, channel, http.StatusUnauthorized, err)
		return err
	}
	if err = transportBodyIdentityMatches(p.nodeID, body); err != nil {
		_ = sendError(ctx, channel, http.StatusUnauthorized, err)
		return err
	}
	m.mu.Lock()
	handler := m.handler
	m.mu.Unlock()
	if handler == nil {
		err = fmt.Errorf("traversal handler is unavailable")
		_ = sendError(ctx, channel, http.StatusServiceUnavailable, err)
		return err
	}
	requestURL := &url.URL{Scheme: "https", Host: "gonzbnet.traversal", Path: requestHeader.Path, RawQuery: requestHeader.RawQuery}
	handlerCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
	defer cancel()
	request := &http.Request{
		Method: requestHeader.Method, URL: requestURL, RequestURI: requestURL.RequestURI(),
		Header: requestHeader.Header.Clone(), Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), RemoteAddr: "gonzbnet:" + p.nodeID,
	}
	request.Header.Set(TransportNodeIDHeader, p.nodeID)
	request = request.WithContext(handlerCtx)
	recorder := newBudgetedRecorder(m.cfg.MaxBodyBytes, m.bodyBudget)
	defer recorder.release()
	handler.ServeHTTP(recorder, request)
	if recorder.err != nil {
		_ = sendError(ctx, channel, http.StatusInternalServerError, recorder.err)
		return recorder.err
	}
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	_, err = sendMessageAndDrain(ctx, channel, responseHeader{StatusCode: status, Header: recorder.header}, recorder.body.Bytes())
	p.mu.Lock()
	p.lastUsed = time.Now().UTC()
	p.mu.Unlock()
	return err
}

func (p *peer) allowChannel(now time.Time, limit int) bool {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	if p.rateWindow.IsZero() || now.Sub(p.rateWindow) >= time.Minute {
		p.rateWindow = now
		p.rateStarts = 0
	}
	if p.rateStarts >= limit {
		return false
	}
	p.rateStarts++
	return true
}

func (p *peer) allowRequest(now time.Time, limit int) bool {
	p.requestRateMu.Lock()
	defer p.requestRateMu.Unlock()
	if p.requestRateWindow.IsZero() || now.Sub(p.requestRateWindow) >= time.Minute {
		p.requestRateWindow = now
		p.requestRateStarts = 0
	}
	if p.requestRateStarts >= limit {
		return false
	}
	p.requestRateStarts++
	return true
}

func (m *Manager) pathAllowed(path string) bool {
	if !safePath(path) {
		return false
	}
	if path == "/.well-known/gonzbnet" {
		return true
	}
	return path == m.cfg.AllowedBasePath || strings.HasPrefix(path, m.cfg.AllowedBasePath+"/")
}

func safePath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n?#%") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (m *Manager) runCoordinator(state *coordinatorState) {
	backoff := time.Second
	for m.ctx.Err() == nil {
		if err := state.client.Connect(m.ctx); err != nil {
			m.setCoordinatorConnected(state, false, err)
			if !waitContext(m.ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		turn, err := state.client.FetchTURNCredentials(m.ctx)
		if err != nil {
			_ = state.client.Close()
			m.setCoordinatorConnected(state, false, err)
			if !waitContext(m.ctx, backoff) {
				return
			}
			continue
		}
		state.mu.Lock()
		state.connected = true
		state.turn = turn
		state.turnFetchedAt = time.Now().UTC()
		state.mu.Unlock()
		m.setCoordinatorConnected(state, true, nil)
		backoff = time.Second
		for m.ctx.Err() == nil {
			envelope, err := state.client.Receive()
			if err != nil {
				m.setCoordinatorConnected(state, false, err)
				_ = state.client.Close()
				break
			}
			_ = m.handleEnvelope(state, envelope)
		}
	}
}

func (m *Manager) handleEnvelope(state *coordinatorState, envelope protocol.Envelope) error {
	publicKey, err := envelope.Verify(time.Now().UTC(), 2*time.Minute)
	if err != nil {
		return err
	}
	if envelope.TargetNodeID != m.nodeID {
		return fmt.Errorf("signaling target mismatch")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if !m.replay.Consume(envelope.SourceNodeID, envelope.Nonce, expiresAt, time.Now().UTC()) {
		return fmt.Errorf("signaling replay rejected")
	}
	if m.cfg.VerifyPeerKey != nil {
		if err := m.cfg.VerifyPeerKey(m.ctx, envelope.SourceNodeID, publicKey); err != nil {
			return err
		}
	}
	switch envelope.MessageType {
	case protocol.MessageConnect:
		if m.nodeID >= envelope.SourceNodeID {
			return nil
		}
		m.mu.Lock()
		p := m.peers[envelope.SourceNodeID]
		if p == nil {
			if len(m.peers) >= m.cfg.MaxPeerConnections && !m.evictOldestIdleLocked() {
				m.mu.Unlock()
				return fmt.Errorf("traversal peer connection pool is full")
			}
			p = &peer{manager: m, nodeID: envelope.SourceNodeID, coordinator: state, connected: make(chan struct{}), done: make(chan struct{}), lastUsed: time.Now().UTC()}
			m.peers[p.nodeID] = p
		}
		m.mu.Unlock()
		p.mu.Lock()
		pc := p.pc
		if pc != nil && p.established && !p.negotiating {
			p.negotiating = true
			p.mu.Unlock()
			go m.restartICE(p, pc)
		} else {
			p.mu.Unlock()
			go m.createOffer(p)
		}
		return nil
	case protocol.MessageOffer:
		return m.acceptOffer(state, envelope)
	case protocol.MessageAnswer:
		return m.acceptAnswer(envelope)
	case protocol.MessageError:
		return fmt.Errorf("coordinator negotiation error")
	default:
		return fmt.Errorf("unsupported signaling message")
	}
}

func (m *Manager) send(state *coordinatorState, envelope protocol.Envelope) error {
	deadline := time.Now().Add(m.cfg.ConnectTimeout)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		connected := state.connected
		state.mu.RUnlock()
		if connected {
			if err := state.client.Send(envelope); err == nil {
				return nil
			}
		}
		if !waitContext(m.ctx, 100*time.Millisecond) {
			break
		}
	}
	return fmt.Errorf("traversal coordinator is unreachable")
}

func (m *Manager) failPeer(p *peer, err error) {
	m.closePeer(p, err, true)
}

func (m *Manager) closePeer(p *peer, err error, reportFailure bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	firstClose := p.err == nil
	if p.err == nil {
		p.err = err
	}
	pc := p.pc
	p.pc = nil
	sessionID := p.sessionID
	p.mu.Unlock()
	p.doneOnce.Do(func() { close(p.done) })
	if reportFailure && firstClose {
		m.observeWithPC(p, pc, 0, 0, err)
	}
	if pc != nil {
		_ = pc.Close()
	}
	m.mu.Lock()
	if m.peers[p.nodeID] == p {
		delete(m.peers, p.nodeID)
	}
	if m.sessions[sessionID] == p {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
}

func (m *Manager) evictOldestIdleLocked() bool {
	type candidate struct {
		peer     *peer
		lastUsed time.Time
	}
	var candidates []candidate
	for _, p := range m.peers {
		if p.active.Load() == 0 && p.inbound.Load() == 0 {
			p.mu.Lock()
			lastUsed := p.lastUsed
			p.mu.Unlock()
			candidates = append(candidates, candidate{peer: p, lastUsed: lastUsed})
		}
	}
	if len(candidates) == 0 {
		return false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].lastUsed.Before(candidates[j].lastUsed) })
	p := candidates[0].peer
	delete(m.peers, p.nodeID)
	go m.closePeer(p, fmt.Errorf("traversal peer evicted from connection pool"), false)
	return true
}

func (m *Manager) reapIdlePeers() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			var stale []*peer
			m.mu.Lock()
			for _, p := range m.peers {
				p.mu.Lock()
				lastUsed := p.lastUsed
				p.mu.Unlock()
				if p.active.Load() == 0 && p.inbound.Load() == 0 && now.Sub(lastUsed) >= m.cfg.IdleTimeout {
					stale = append(stale, p)
					delete(m.peers, p.nodeID)
				}
			}
			m.mu.Unlock()
			for _, p := range stale {
				m.closePeer(p, fmt.Errorf("traversal peer idle timeout"), false)
			}
		}
	}
}

func (m *Manager) setCoordinatorConnected(state *coordinatorState, connected bool, err error) {
	state.mu.Lock()
	wasConnected := state.connected
	state.connected = connected
	if wasConnected && !connected {
		state.reconnects++
	}
	reconnects := state.reconnects
	state.mu.Unlock()
	if m.cfg.Observe != nil {
		failure := ""
		if err != nil {
			failure = safeFailure(err)
		}
		m.cfg.Observe(Observation{Coordinator: state.config.URL, Reachable: connected, Reconnects: reconnects, Failure: failure})
	}
}

func (m *Manager) observe(p *peer, sent, received int64, err error) {
	if m.cfg.Observe == nil || p == nil {
		return
	}
	p.mu.Lock()
	pc := p.pc
	p.mu.Unlock()
	m.observeWithPC(p, pc, sent, received, err)
}

func (m *Manager) observeWithPC(p *peer, pc *webrtc.PeerConnection, sent, received int64, err error) {
	if m.cfg.Observe == nil || p == nil {
		return
	}
	p.mu.Lock()
	pathType := p.pathType
	p.mu.Unlock()
	iceState := ""
	rttMS := int64(0)
	if pc != nil {
		iceState = pc.ICEConnectionState().String()
		rttMS = selectedRTTMS(pc)
	}
	failure := ""
	if err != nil {
		failure = safeFailure(err)
	}
	p.coordinator.mu.RLock()
	reconnects := p.coordinator.reconnects
	p.coordinator.mu.RUnlock()
	m.cfg.Observe(Observation{Coordinator: p.coordinator.config.URL, PeerNodeID: p.nodeID, Reachable: err == nil, PathType: pathType, ICEState: iceState, RTTMS: rttMS, Reconnects: reconnects, BytesSent: sent, BytesReceived: received, Failure: failure})
}

func safeFailure(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(value, "timed out"), strings.Contains(value, "timeout"):
		return "timeout"
	case strings.Contains(value, "identity"), strings.Contains(value, "public key"), strings.Contains(value, "signature"):
		return "identity_verification_failed"
	case strings.Contains(value, "coordinator"):
		return "coordinator_unreachable"
	case strings.Contains(value, "data channel"), strings.Contains(value, "sctp"):
		return "data_channel_failed"
	case strings.Contains(value, "ice"), strings.Contains(value, "candidate"):
		return "ice_failed"
	default:
		return "transport_failed"
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
	states := make([]*coordinatorState, 0, len(m.coordinators))
	for _, state := range m.coordinators {
		states = append(states, state)
	}
	peers := make([]*peer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.peers = make(map[string]*peer)
	m.mu.Unlock()
	for _, state := range states {
		_ = state.client.Close()
	}
	for _, p := range peers {
		m.closePeer(p, fmt.Errorf("traversal manager closed"), false)
	}
	return nil
}

func selectedPathType(pc *webrtc.PeerConnection) string {
	if pc == nil || pc.SCTP() == nil || pc.SCTP().Transport() == nil || pc.SCTP().Transport().ICETransport() == nil {
		return "unknown"
	}
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return "unknown"
	}
	if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
		return "relay"
	}
	return "direct"
}

func selectedRTTMS(pc *webrtc.PeerConnection) int64 {
	if pc == nil {
		return 0
	}
	for _, item := range pc.GetStats() {
		pair, ok := item.(webrtc.ICECandidatePairStats)
		if ok && pair.Nominated && pair.State == webrtc.StatsICECandidatePairStateSucceeded && pair.CurrentRoundTripTime > 0 {
			return int64(pair.CurrentRoundTripTime * 1000)
		}
	}
	return 0
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func randomID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}
