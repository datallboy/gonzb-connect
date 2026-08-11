package ice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"golang.org/x/net/http/httpguts"
)

type requestHeader struct {
	Method   string      `json:"method"`
	Path     string      `json:"path"`
	RawQuery string      `json:"raw_query,omitempty"`
	Header   http.Header `json:"header"`
}

type responseHeader struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
}

const (
	dataChannelHighWaterMark = 64 << 10
	dataChannelLowWaterMark  = 32 << 10
)

func sendMessage(ctx context.Context, channel *webrtc.DataChannel, header any, body []byte) (int64, error) {
	return sendMessageWithDrain(ctx, channel, header, body, false)
}

func sendMessageAndDrain(ctx context.Context, channel *webrtc.DataChannel, header any, body []byte) (int64, error) {
	return sendMessageWithDrain(ctx, channel, header, body, true)
}

func sendMessageWithDrain(ctx context.Context, channel *webrtc.DataChannel, header any, body []byte, drain bool) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if channel == nil {
		return 0, fmt.Errorf("data channel is unavailable")
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return 0, err
	}
	if len(headerBytes) == 0 || len(headerBytes) > maxHeaderBytes {
		return 0, fmt.Errorf("data channel header exceeds bounds")
	}
	bufferLow := make(chan struct{}, 1)
	channel.SetBufferedAmountLowThreshold(dataChannelLowWaterMark)
	channel.OnBufferedAmountLow(func() {
		select {
		case bufferLow <- struct{}{}:
		default:
		}
	})
	defer channel.OnBufferedAmountLow(func() {})
	if err := sendFrameWithFlowControl(ctx, channel, bufferLow, frameHeader, headerBytes); err != nil {
		return 0, err
	}
	total := int64(len(headerBytes) + 1)
	for len(body) > 0 {
		size := min(len(body), dataFrameBytes)
		if err := sendFrameWithFlowControl(ctx, channel, bufferLow, frameData, body[:size]); err != nil {
			return total, err
		}
		total += int64(size + 1)
		body = body[size:]
	}
	if err := sendFrameWithFlowControl(ctx, channel, bufferLow, frameEnd, nil); err != nil {
		return total, err
	}
	if drain {
		channel.SetBufferedAmountLowThreshold(0)
		if err := waitForBufferedAmount(ctx, channel, bufferLow, 0); err != nil {
			return total + 1, err
		}
	}
	return total + 1, nil
}

func sendFrameWithFlowControl(ctx context.Context, channel *webrtc.DataChannel, bufferLow <-chan struct{}, kind byte, payload []byte) error {
	if err := waitForBufferedAmount(ctx, channel, bufferLow, dataChannelHighWaterMark); err != nil {
		return err
	}
	return sendFrame(channel, kind, payload)
}

func waitForBufferedAmount(ctx context.Context, channel *webrtc.DataChannel, bufferLow <-chan struct{}, threshold uint64) error {
	for channel != nil && channel.BufferedAmount() > threshold {
		if channel.ReadyState() != webrtc.DataChannelStateOpen {
			return fmt.Errorf("data channel closed while waiting for send capacity")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-bufferLow:
			timer.Stop()
		case <-timer.C:
		}
	}
	if channel == nil {
		return fmt.Errorf("data channel is unavailable")
	}
	return nil
}

func sendFrame(channel *webrtc.DataChannel, kind byte, payload []byte) error {
	if channel == nil {
		return fmt.Errorf("data channel is unavailable")
	}
	if kind == frameData && len(payload) > dataFrameBytes {
		return fmt.Errorf("data channel frame exceeds %d bytes", dataFrameBytes)
	}
	frame := make([]byte, len(payload)+1)
	frame[0] = kind
	copy(frame[1:], payload)
	return channel.Send(frame)
}

func receiveMessage(ctx context.Context, messages <-chan []byte, header any, maxBodyBytes int64) ([]byte, int64, error) {
	return receiveMessageWithBudget(ctx, messages, header, maxBodyBytes, nil)
}

func receiveMessageWithBudget(ctx context.Context, messages <-chan []byte, header any, maxBodyBytes int64, budget *byteBudget) ([]byte, int64, error) {
	first, err := nextFrame(ctx, messages)
	if err != nil {
		return nil, 0, err
	}
	if len(first) < 2 || first[0] != frameHeader || len(first)-1 > maxHeaderBytes {
		return nil, int64(len(first)), fmt.Errorf("malformed data channel header")
	}
	decoder := json.NewDecoder(bytes.NewReader(first[1:]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(header); err != nil {
		return nil, int64(len(first)), fmt.Errorf("decode data channel header: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, int64(len(first)), fmt.Errorf("decode data channel header: trailing data")
	}
	total := int64(len(first))
	body := make([]byte, 0)
	reserved := int64(0)
	success := false
	defer func() {
		if budget != nil && reserved > 0 && !success {
			budget.release(reserved)
		}
	}()
	for {
		frame, err := nextFrame(ctx, messages)
		if err != nil {
			return nil, total, err
		}
		total += int64(len(frame))
		if len(frame) == 0 {
			return nil, total, fmt.Errorf("empty data channel frame")
		}
		switch frame[0] {
		case frameData:
			payloadBytes := int64(len(frame) - 1)
			if len(frame)-1 > dataFrameBytes || int64(len(body))+payloadBytes > maxBodyBytes {
				return nil, total, fmt.Errorf("data channel body exceeds bounds")
			}
			if budget != nil && !budget.reserve(payloadBytes) {
				return nil, total, fmt.Errorf("traversal in-flight body budget exhausted")
			}
			reserved += payloadBytes
			body = append(body, frame[1:]...)
		case frameEnd:
			if len(frame) != 1 {
				return nil, total, fmt.Errorf("malformed data channel end frame")
			}
			success = true
			return body, total, nil
		default:
			return nil, total, fmt.Errorf("unexpected data channel frame type")
		}
	}
}

type byteBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *byteBudget) reserve(size int64) bool {
	if b == nil || size <= 0 {
		return true
	}
	for {
		used := b.used.Load()
		if size > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (b *byteBudget) release(size int64) {
	if b != nil && size > 0 {
		b.used.Add(-size)
	}
}

func nextFrame(ctx context.Context, messages <-chan []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame, ok := <-messages:
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		return frame, nil
	}
}

func readLimitedWithBudget(reader io.Reader, limit int64, budget *byteBudget) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	buffer := &budgetBuffer{limit: limit, budget: budget}
	if _, err := io.Copy(buffer, reader); err != nil {
		buffer.release()
		return nil, err
	}
	return buffer.buffer.Bytes(), nil
}

type budgetBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	budget   *byteBudget
	reserved int64
}

func (b *budgetBuffer) Write(payload []byte) (int, error) {
	if int64(b.buffer.Len())+int64(len(payload)) > b.limit {
		return 0, fmt.Errorf("request body exceeds traversal limit")
	}
	if !b.budget.reserve(int64(len(payload))) {
		return 0, fmt.Errorf("traversal in-flight body budget exhausted")
	}
	b.reserved += int64(len(payload))
	return b.buffer.Write(payload)
}

func (b *budgetBuffer) release() {
	if b != nil && b.reserved > 0 {
		b.budget.release(b.reserved)
		b.reserved = 0
	}
}

func transportIdentityMatches(peerNodeID string, header http.Header) error {
	values := header.Values("Authorization")
	if len(values) > 1 {
		return fmt.Errorf("multiple traversal authorization headers")
	}
	authorization := ""
	if len(values) == 1 {
		authorization = strings.TrimSpace(values[0])
	}
	if authorization == "" {
		return nil
	}
	if !strings.HasPrefix(authorization, "GoNZBNet ") {
		return fmt.Errorf("unsupported traversal authorization")
	}
	allowed := map[string]struct{}{
		"node_id": {}, "timestamp": {}, "nonce": {}, "signature": {},
	}
	parsed := make(map[string]string, len(allowed))
	for _, part := range strings.Split(strings.TrimSpace(strings.TrimPrefix(authorization, "GoNZBNet")), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok {
			return fmt.Errorf("invalid traversal authorization field")
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown traversal authorization field")
		}
		if _, exists := parsed[key]; exists {
			return fmt.Errorf("duplicate traversal authorization field")
		}
		if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
			return fmt.Errorf("invalid traversal authorization value")
		}
		value = value[1 : len(value)-1]
		if strings.ContainsAny(value, "\"\\\r\n") {
			return fmt.Errorf("invalid traversal authorization value")
		}
		parsed[key] = value
	}
	if len(parsed) != len(allowed) {
		return fmt.Errorf("signed traversal request omits required fields")
	}
	if parsed["node_id"] != peerNodeID {
		return fmt.Errorf("signed request author does not match authenticated traversal peer")
	}
	return nil
}

func validateHTTPHeader(header http.Header) error {
	for name, values := range header {
		if name != http.CanonicalHeaderKey(name) || !httpguts.ValidHeaderFieldName(name) || len(values) > 16 {
			return fmt.Errorf("invalid traversal HTTP header")
		}
		switch strings.ToLower(name) {
		case "connection", "content-length", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			return fmt.Errorf("hop-by-hop traversal HTTP header is not allowed")
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return fmt.Errorf("invalid traversal HTTP header value")
			}
		}
	}
	return nil
}

func transportBodyIdentityMatches(peerNodeID string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		return nil
	}
	for _, field := range []string{"node_id", "author_node_id", "requesting_node_id"} {
		raw, exists := object[field]
		if !exists {
			continue
		}
		var claimed string
		if json.Unmarshal(raw, &claimed) == nil && strings.TrimSpace(claimed) != "" && strings.TrimSpace(claimed) != peerNodeID {
			return fmt.Errorf("signed request author does not match authenticated traversal peer")
		}
	}
	return nil
}

func sendError(ctx context.Context, channel *webrtc.DataChannel, status int, _ error) error {
	_, sendErr := sendMessageAndDrain(ctx, channel, responseHeader{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}}, []byte(http.StatusText(status)))
	return sendErr
}

type boundedRecorder struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	limit    int64
	err      error
	budget   *byteBudget
	reserved int64
}

func newBoundedRecorder(limit int64) *boundedRecorder {
	return &boundedRecorder{header: make(http.Header), limit: limit}
}

func newBudgetedRecorder(limit int64, budget *byteBudget) *boundedRecorder {
	return &boundedRecorder{header: make(http.Header), limit: limit, budget: budget}
}
func (r *boundedRecorder) Header() http.Header { return r.header }
func (r *boundedRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *boundedRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.err != nil {
		return 0, r.err
	}
	if int64(r.body.Len()+len(payload)) > r.limit {
		r.err = fmt.Errorf("traversal response body exceeds limit")
		return 0, r.err
	}
	if !r.budget.reserve(int64(len(payload))) {
		r.err = fmt.Errorf("traversal in-flight body budget exhausted")
		return 0, r.err
	}
	r.reserved += int64(len(payload))
	return r.body.Write(payload)
}

func (r *boundedRecorder) release() {
	if r != nil && r.reserved > 0 {
		r.budget.release(r.reserved)
		r.reserved = 0
	}
}

type budgetedReadCloser struct {
	reader  *bytes.Reader
	budget  *byteBudget
	size    int64
	release atomic.Bool
}

func newBudgetedReadCloser(payload []byte, budget *byteBudget) io.ReadCloser {
	return &budgetedReadCloser{reader: bytes.NewReader(payload), budget: budget, size: int64(len(payload))}
}

func (r *budgetedReadCloser) Read(payload []byte) (int, error) {
	n, err := r.reader.Read(payload)
	if err == io.EOF {
		_ = r.Close()
	}
	return n, err
}

func (r *budgetedReadCloser) Close() error {
	if r != nil && r.release.CompareAndSwap(false, true) {
		r.budget.release(r.size)
	}
	return nil
}
