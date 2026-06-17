// Package ipc implements the SkyNet STDIO-based JSON-RPC bus used by the
// cloudflared sidecar.
//
// Wire protocol (one JSON object per line on stdin/stdout):
//
//   Request  -> {"jsonrpc":"2.0","method":"init","params":{...},"id":42}
//   Response -> {"jsonrpc":"2.0","result":{...},"id":42}
//   Error    -> {"jsonrpc":"2.0","error":{"code":1,"message":"..."},"id":42}
//   Notify   -> {"jsonrpc":"2.0","method":"state_changed","params":{...}}
//
// Stderr is reserved for sidecar-internal logging; the SkyNet runtime ignores
// it so we can keep debug traces out of the IPC stream.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"
)

// Request is the on-the-wire shape of an incoming JSON-RPC call from SkyNet.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// Response is the reply shape; the SkyNet dispatcher matches responses by ID.
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
	ID      any    `json:"id,omitempty"`
}

// Notification is a server-to-runtime push message (state change, log tail,
// heartbeat). It has no ID and expects no reply.
type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// Handler is the bridge between the wire format and the SSI component. The
// sidecar's main loop registers one handler per component method.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

// maxConcurrentRequests bounds the number of in-flight handler goroutines.
// Incoming requests beyond this limit block until a slot frees up, preventing
// an attacker from exhausting memory by flooding stdin with JSON-RPC calls.
const maxConcurrentRequests = 100

// Bus reads requests from `in` and writes responses / notifications to `out`.
// It serialises writes so that multiple goroutines (e.g. the component loop
// and a notification pump) don't interleave their JSON lines.
type Bus struct {
	in       *bufio.Reader
	out      io.Writer
	mu       sync.Mutex
	handlers map[string]Handler
	sem      chan struct{} // 信号量，限制并发处理数量

	// ctx is the background context for handlers; cancelled when Close fires.
	ctx    context.Context
	cancel context.CancelFunc
}

func NewBus(in io.Reader, out io.Writer) *Bus {
	ctx, cancel := context.WithCancel(context.Background())
	return &Bus{
		in:       bufio.NewReader(in),
		out:      out,
		handlers: make(map[string]Handler),
		sem:      make(chan struct{}, maxConcurrentRequests),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Register binds a handler name to a function. Names match the "method" field
// of incoming JSON-RPC requests.
func (b *Bus) Register(name string, h Handler) { b.handlers[name] = h }

// Notify pushes an unsolicited notification to the runtime. Safe to call from
// any goroutine.
func (b *Bus) Notify(method string, params any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return writeJSON(b.out, Notification{JSONRPC: "2.0", Method: method, Params: params})
}

// Run dispatches one request per line from stdin until EOF or a cancellation.
// Returns the first read error (typically io.EOF on graceful shutdown).
// Each request is dispatched inside a goroutine, but the concurrency is bounded by
// the semaphore so a burst of traffic cannot OOM the sidecar.
func (b *Bus) Run() error {
	for {
		line, err := b.in.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		select {
		case b.sem <- struct{}{}:
		case <-b.ctx.Done():
			// Close() was called; drain one more time so we don't leak a
			// goroutine. Treat as a graceful shutdown.
			return nil
		}
		go func(data []byte) {
			defer func() { <-b.sem }()
			b.dispatch(data)
		}(line)
	}
}

// Close cancels the internal context and lets in-flight handlers exit.
func (b *Bus) Close() { b.cancel() }

// Done returns a channel that is closed when the bus is closed. Useful for
// signalling background goroutines (e.g. the heartbeat) to exit.
func (b *Bus) Done() <-chan struct{} { return b.ctx.Done() }

// ---- private --------------------------------------------------------------

// dispatch parses and runs a single request. It is always called inside a
// goroutine; we do a deferred recover so a bug in one handler cannot take
// down the whole sidecar (which would also take the cloudflared child with
// it and require a full supervisor restart).
func (b *Bus) dispatch(raw []byte) {
	defer func() {
		if r := recover(); r != nil {
			DebugLog("handler panic recovered: %v\n%s", r, debug.Stack())
			// Best-effort error response. We don't know the request ID, so
			// leave it nil — SkyNet will see a malformed response and log it,
			// but the sidecar stays alive.
			b.writeResponse(nil, nil, fmt.Errorf("internal handler panic: %v", r))
		}
	}()
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		b.writeResponse(req.ID, nil, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	h, ok := b.handlers[req.Method]
	if !ok {
		b.writeResponse(req.ID, nil, fmt.Errorf("unknown method %q", req.Method))
		return
	}
	// Handlers may be long-running (e.g. Stop() with a graceful wait); ensure
	// they respect the bus context so Close() unblocks them.
	select {
	case <-b.ctx.Done():
		b.writeResponse(req.ID, nil, fmt.Errorf("bus closed"))
		return
	default:
	}
	result, herr := h(b.ctx, req.Params)
	b.writeResponse(req.ID, result, herr)
}

func (b *Bus) writeResponse(id any, result any, err error) {
	resp := Response{JSONRPC: "2.0", ID: id}
	if err != nil {
		resp.Error = map[string]any{"code": -1, "message": err.Error()}
	} else {
		resp.Result = result
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = writeJSON(b.out, resp)
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// DebugLog writes a timestamped line to stderr. The runtime ignores stderr,
// but developers can redirect it to a log file when debugging.
func DebugLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[sidecar] "+format+"\n", args...)
}
