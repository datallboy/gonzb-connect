package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/datallboy/gonzb-connect/protocol"
	"github.com/gorilla/websocket"
)

type Identity interface {
	NodeID(context.Context) (string, error)
	PublicKey(context.Context) (ed25519.PublicKey, error)
}

type TURNResponse struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	TTLSeconds int      `json:"ttl_seconds"`
	URIs       []string `json:"uris"`
	STUNURIs   []string `json:"stun_uris,omitempty"`
}

type Client struct {
	baseURL                string
	credential             string
	identity               Identity
	mu                     sync.Mutex
	conn                   *websocket.Conn
	allowPrivateICEServers bool
	allowedICEServerHosts  map[string]struct{}
}

func New(baseURL, credential string, identity Identity) *Client {
	return &Client{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), credential: strings.TrimSpace(credential), identity: identity}
}

func (c *Client) SetAllowPrivateICEServers(allow bool) { c.allowPrivateICEServers = allow }

func (c *Client) SetAllowedICEServerHosts(hosts []string) {
	c.allowedICEServerHosts = make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		c.allowedICEServerHosts[normalizeServerHost(host)] = struct{}{}
	}
}

func (c *Client) Connect(ctx context.Context) error {
	if c == nil || c.identity == nil || c.credential == "" {
		return fmt.Errorf("coordinator client is not configured")
	}
	nodeID, err := c.identity.NodeID(ctx)
	if err != nil {
		return err
	}
	publicKey, err := c.identity.PublicKey(ctx)
	if err != nil {
		return err
	}
	endpoint, err := c.endpoint("/v1/signal", "wss")
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("node_id", nodeID)
	query.Set("public_key", base64.RawURLEncoding.EncodeToString(publicKey))
	endpoint.RawQuery = query.Encode()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+c.credential)
	conn, response, err := websocket.DefaultDialer.DialContext(ctx, endpoint.String(), headers)
	if err != nil {
		if response != nil {
			return fmt.Errorf("coordinator registration status=%d: %w", response.StatusCode, err)
		}
		return err
	}
	conn.SetReadLimit(protocol.MaxMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPingHandler(func(message string) error {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(5*time.Second))
	})
	c.mu.Lock()
	old := c.conn
	c.conn = conn
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *Client) Send(envelope protocol.Envelope) error {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(payload) > protocol.MaxMessageBytes {
		return fmt.Errorf("signaling message exceeds %d bytes", protocol.MaxMessageBytes)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("coordinator is disconnected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, payload)
}

func (c *Client) Receive() (protocol.Envelope, error) {
	var envelope protocol.Envelope
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return envelope, fmt.Errorf("coordinator is disconnected")
	}
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return envelope, err
	}
	if messageType != websocket.TextMessage || len(payload) > protocol.MaxMessageBytes {
		return envelope, fmt.Errorf("signaling message exceeds limit")
	}
	if err := decodeStrictJSON(payload, &envelope); err != nil {
		return envelope, fmt.Errorf("decode signaling envelope: %w", err)
	}
	return envelope, nil
}

func (c *Client) FetchTURNCredentials(ctx context.Context) (TURNResponse, error) {
	var out TURNResponse
	if c == nil || c.identity == nil || c.credential == "" {
		return out, fmt.Errorf("coordinator client is not configured")
	}
	nodeID, err := c.identity.NodeID(ctx)
	if err != nil {
		return out, err
	}
	publicKey, err := c.identity.PublicKey(ctx)
	if err != nil {
		return out, err
	}
	endpoint, err := c.endpoint("/v1/turn-credentials", "https")
	if err != nil {
		return out, err
	}
	query := endpoint.Query()
	query.Set("node_id", nodeID)
	query.Set("public_key", base64.RawURLEncoding.EncodeToString(publicKey))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("TURN credential status=%d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return out, err
	}
	if len(raw) > 64<<10 {
		return out, fmt.Errorf("TURN credential response exceeds 64 KiB")
	}
	if err := decodeStrictJSON(raw, &out); err != nil {
		return out, err
	}
	if err := validateTURNResponse(ctx, out, c.allowPrivateICEServers, c.allowedICEServerHosts); err != nil {
		return TURNResponse{}, err
	}
	return out, nil
}

func decodeStrictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("JSON response contains trailing data")
	}
	return nil
}

func validateTURNResponse(ctx context.Context, response TURNResponse, allowPrivate bool, allowedHosts map[string]struct{}) error {
	if response.TTLSeconds <= 0 || response.TTLSeconds > 600 || len(response.Username) == 0 || len(response.Username) > 128 || len(response.Credential) == 0 || len(response.Credential) > 256 {
		return fmt.Errorf("invalid TURN credential response")
	}
	credential, err := base64.StdEncoding.DecodeString(response.Credential)
	if err != nil || len(credential) != 20 {
		return fmt.Errorf("invalid TURN REST credential")
	}
	if len(response.URIs) == 0 || len(response.URIs) > 4 || len(response.STUNURIs) == 0 || len(response.STUNURIs) > 2 {
		return fmt.Errorf("invalid ICE server count")
	}
	for _, raw := range response.URIs {
		if err := validateICEServer(ctx, raw, true, allowPrivate, allowedHosts); err != nil {
			return err
		}
	}
	for _, raw := range response.STUNURIs {
		if err := validateICEServer(ctx, raw, false, allowPrivate, allowedHosts); err != nil {
			return err
		}
	}
	return nil
}

func validateICEServer(ctx context.Context, raw string, turn, allowPrivate bool, allowedHosts map[string]struct{}) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque == "" || strings.ContainsAny(parsed.Opaque, "@/#") {
		return fmt.Errorf("invalid ICE server URI")
	}
	if turn {
		if parsed.Scheme != "turn" && parsed.Scheme != "turns" {
			return fmt.Errorf("invalid TURN server URI")
		}
		if parsed.RawQuery != "" {
			values := parsed.Query()["transport"]
			if len(parsed.Query()) != 1 || len(values) != 1 || (values[0] != "udp" && values[0] != "tcp") {
				return fmt.Errorf("invalid TURN transport")
			}
		}
	} else if (parsed.Scheme != "stun" && parsed.Scheme != "stuns") || parsed.RawQuery != "" {
		return fmt.Errorf("invalid STUN server URI")
	}
	hostPort := parsed.Opaque
	if index := strings.IndexByte(hostPort, '?'); index >= 0 {
		hostPort = hostPort[:index]
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	host = normalizeServerHost(host)
	if host == "" {
		return fmt.Errorf("ICE server URI omits a host")
	}
	if _, allowed := allowedHosts[host]; !allowed {
		return fmt.Errorf("ICE server host is not configured")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("resolve ICE server host")
	}
	if !allowPrivate {
		for _, address := range addresses {
			ip := address.IP
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return fmt.Errorf("ICE server resolves to a prohibited address")
			}
		}
	}
	return nil
}

func normalizeServerHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]")), ".")
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *Client) endpoint(path, secureScheme string) (*url.URL, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("invalid coordinator URL")
	}
	switch parsed.Scheme {
	case "https":
		parsed.Scheme = secureScheme
	default:
		return nil, fmt.Errorf("coordinator URL must use https")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}
