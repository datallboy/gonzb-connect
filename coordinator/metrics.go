package coordinator

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// serverMetrics intentionally contains only aggregate counters. Node IDs,
// source addresses, credentials, SDP, candidates, and session IDs must never
// become metric labels.
type serverMetrics struct {
	authSucceeded           atomic.Uint64
	authRejected            atomic.Uint64
	registrationsRejected   atomic.Uint64
	activeRegistrations     atomic.Int64
	activeNegotiations      atomic.Int64
	signalingAccepted       atomic.Uint64
	signalingRejected       atomic.Uint64
	signalingDelivered      atomic.Uint64
	signalingBytesDelivered atomic.Uint64
	offlineTargets          atomic.Uint64
	negotiationsRejected    atomic.Uint64
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	metrics := []struct {
		name  string
		help  string
		kind  string
		value uint64
	}{
		{"gonzb_connect_auth_succeeded_total", "Successful coordinator authentications.", "counter", s.metrics.authSucceeded.Load()},
		{"gonzb_connect_auth_rejected_total", "Rejected coordinator authentications.", "counter", s.metrics.authRejected.Load()},
		{"gonzb_connect_registrations_rejected_total", "Rejected WebSocket registrations.", "counter", s.metrics.registrationsRejected.Load()},
		{"gonzb_connect_active_registrations", "Current WebSocket registrations.", "gauge", uint64(max(s.metrics.activeRegistrations.Load(), 0))},
		{"gonzb_connect_active_negotiations", "Current in-memory ICE negotiations.", "gauge", uint64(max(s.metrics.activeNegotiations.Load(), 0))},
		{"gonzb_connect_signaling_accepted_total", "Accepted signed signaling envelopes.", "counter", s.metrics.signalingAccepted.Load()},
		{"gonzb_connect_signaling_rejected_total", "Rejected signaling messages.", "counter", s.metrics.signalingRejected.Load()},
		{"gonzb_connect_signaling_delivered_total", "Signaling envelope deliveries.", "counter", s.metrics.signalingDelivered.Load()},
		{"gonzb_connect_signaling_bytes_delivered_total", "Signaling bytes delivered.", "counter", s.metrics.signalingBytesDelivered.Load()},
		{"gonzb_connect_offline_targets_total", "Accepted envelopes whose target had no registration.", "counter", s.metrics.offlineTargets.Load()},
		{"gonzb_connect_negotiations_rejected_total", "Negotiations rejected by session or rate policy.", "counter", s.metrics.negotiationsRejected.Load()},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", metric.name, metric.help, metric.name, metric.kind, metric.name, metric.value)
	}
}
