// Package inspector implements incremental parsing of TLS ClientHello
// messages from segmented TCP streams for the DPI hot path
// (SYSTEM_DESIGN.md §3.2: the desync branch decides per-flow actions from
// SNI/ALPN/ECH of the first ClientHello).
//
// A Stream holds the per-connection parse state. TCP segments are fed in
// order with Feed; a ClientHello spread over 2–4 segments (post-quantum
// hellos of ~1.4 KB routinely fragment) is reassembled in a reusable
// per-stream buffer capped at 8 KB. The steady-state hot path performs no
// heap allocations: a ClientHello that arrives whole in the first segment
// is parsed in place and the returned SNI/ALPN are subslices of that
// segment with no copy.
package inspector

import "errors"

// Sentinel errors returned by Stream.Feed. They are never wrapped, so both
// direct comparison and errors.Is work.
var (
	// ErrNeedMore reports that the bytes seen so far are a valid TLS
	// ClientHello prefix but the message is not complete yet.
	ErrNeedMore = errors.New("inspector: valid ClientHello prefix, need more data")

	// ErrNotTLS reports that the stream does not start with a TLS
	// ClientHello record (wrong content type, wrong handshake message
	// type, or not TLS at all).
	ErrNotTLS = errors.New("inspector: stream does not start with a TLS ClientHello")

	// ErrMalformed reports that the bytes looked like a TLS ClientHello
	// but violate protocol structure: zero or oversized record length,
	// bad version, body field overflow, extension overflow, a
	// multi-record handshake message, or a message larger than the
	// reassembly cap.
	ErrMalformed = errors.New("inspector: malformed TLS ClientHello")
)

// Result is the outcome of feeding a segment to a Stream.
//
// SNI and ALPN are read-only subslices of either the segment passed to the
// Feed call that completed the parse or the stream's internal reassembly
// buffer; they are never copied. They stay valid until the next Feed or
// Reset call on the same Stream (and, for the fast path, until the caller
// reuses the segment buffer).
type Result struct {
	// IsTLS is true when the bytes seen so far form a valid TLS
	// ClientHello prefix (it is also true while NeedMore is set).
	IsTLS bool
	// SNIFound is true when the server_name extension contains a
	// non-empty host_name entry.
	SNIFound bool
	// SNI holds the first host_name from the server_name extension.
	// Meaningful only when SNIFound is true.
	SNI []byte
	// ALPN holds the first protocol name from the ALPN extension, or nil
	// when the extension is absent or carries no names.
	ALPN []byte
	// ECH is true when an Encrypted Client Hello extension is present
	// (0xfe0d, or the legacy draft code point 0xff0d). Per lab data such
	// flows must go to TUNNEL, never DESYNC.
	ECH bool
	// NeedMore is true when the ClientHello is not complete yet.
	NeedMore bool
}
