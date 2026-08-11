package client

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestValidateTURNResponse(t *testing.T) {
	valid := TURNResponse{
		Username: "1700000000:blinded-account", Credential: base64.StdEncoding.EncodeToString(make([]byte, 20)), TTLSeconds: 600,
		URIs:     []string{"turn:203.0.113.1:3478?transport=udp", "turns:203.0.113.1:5349?transport=tcp"},
		STUNURIs: []string{"stun:203.0.113.1:3478"},
	}
	allowed := map[string]struct{}{"203.0.113.1": {}}
	if err := validateTURNResponse(context.Background(), valid, false, allowed); err != nil {
		t.Fatal(err)
	}
	tests := map[string]TURNResponse{
		"private target": func() TURNResponse { item := valid; item.URIs = []string{"turn:10.0.0.1:3478"}; return item }(),
		"wrong scheme":   func() TURNResponse { item := valid; item.URIs = []string{"http:203.0.113.1:3478"}; return item }(),
		"extra query": func() TURNResponse {
			item := valid
			item.URIs = []string{"turn:203.0.113.1:3478?transport=udp&peer=internal"}
			return item
		}(),
		"long ttl":       func() TURNResponse { item := valid; item.TTLSeconds = 601; return item }(),
		"bad credential": func() TURNResponse { item := valid; item.Credential = "not-base64"; return item }(),
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateTURNResponse(context.Background(), response, false, allowed); err == nil {
				t.Fatal("unsafe TURN credential response was accepted")
			}
		})
	}
	if err := validateTURNResponse(context.Background(), valid, false, map[string]struct{}{"198.51.100.1": {}}); err == nil {
		t.Fatal("unconfigured ICE server host was accepted")
	}
}
