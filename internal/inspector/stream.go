package inspector

// maxAccumulate caps ClientHello reassembly per stream. Real-world
// ClientHellos fit comfortably: even post-quantum hellos (ML-KEM key
// share) are ~1.4–1.8 KB.
const maxAccumulate = 8192

type streamState uint8

const (
	stateFresh      streamState = iota // no bytes seen yet
	stateCollecting                    // partial ClientHello in acc
	stateDone                          // terminal: ClientHello parsed
	stateFailed                        // terminal: stream rejected
)

// Stream incrementally parses the first TLS ClientHello of one TCP stream
// (one flow = one Stream). Feed must be called with the stream's data
// segments in arrival order. A Stream is not safe for concurrent use; the
// hot path drives it from a single capture goroutine.
type Stream struct {
	state streamState
	// acc reassembles a fragmented ClientHello. It is allocated once (8 KB
	// capacity) on the first fragmented feed and then reused by every
	// later feed and by Reset; appends after warm-up never reallocate.
	acc []byte
	res Result
	err error
}

// NewStream returns a Stream ready to parse a new connection.
func NewStream() *Stream { return &Stream{} }

// Reset returns the Stream to its pristine state, keeping the reassembly
// buffer (and its capacity) for reuse. Results returned earlier become
// invalid.
func (s *Stream) Reset() {
	s.state = stateFresh
	s.acc = s.acc[:0]
	s.res = Result{}
	s.err = nil
}

// Done reports whether the Stream reached a terminal state: the
// ClientHello was parsed or the stream was rejected. Feeding a terminal
// Stream is a no-op that returns the cached outcome.
func (s *Stream) Done() bool {
	return s.state == stateDone || s.state == stateFailed
}

// Feed consumes the next in-order data segment of the stream and returns
// the current parse outcome:
//
//   - complete ClientHello: a Result with NeedMore=false and a nil error
//     (IsTLS is true; SNIFound/SNI/ALPN/ECH describe the message);
//   - valid prefix, message incomplete: Result{IsTLS:true, NeedMore:true}
//     and ErrNeedMore;
//   - rejected stream: a zero Result and ErrNotTLS or ErrMalformed.
//
// Fast path: when the very first segment holds a complete ClientHello, it
// is parsed in place — zero copies, zero allocations — and the returned
// SNI/ALPN are subslices of that segment.
//
// All errors are the package sentinels; compare with errors.Is.
func (s *Stream) Feed(seg []byte) (Result, error) {
	switch s.state {
	case stateDone:
		return s.res, nil
	case stateFailed:
		return s.res, s.err
	}

	// Fast path: the very first segment.
	if s.state == stateFresh {
		res, err := parseClientHello(seg)
		switch {
		case err == nil:
			s.state, s.res, s.err = stateDone, res, nil
			return s.res, nil
		case err == ErrNeedMore:
			if len(seg) == 0 {
				// Nothing learned yet; stay fresh so a later
				// segment can still take the fast path.
				return Result{IsTLS: true, NeedMore: true}, ErrNeedMore
			}
			// Valid prefix of a fragmented ClientHello: fall
			// through to reassembly.
		default:
			s.state, s.res, s.err = stateFailed, Result{}, err
			return s.res, s.err
		}
	}

	// Slow path: reassemble across segments in acc, bounded by
	// maxAccumulate, re-parsing as bytes arrive.
	s.state = stateCollecting
	for {
		need, err := needBytes(s.acc)
		if err != nil {
			s.state, s.res, s.err = stateFailed, Result{}, err
			return s.res, s.err
		}
		if len(s.acc) >= need {
			// Every byte of the ClientHello is in acc.
			res, perr := parseClientHello(s.acc)
			if perr == nil {
				s.state, s.res, s.err = stateDone, res, nil
				return s.res, nil
			}
			// perr cannot be ErrNeedMore here: the length
			// requirement derived by needBytes is met.
			s.state, s.res, s.err = stateFailed, Result{}, perr
			return s.res, s.err
		}
		if len(seg) == 0 {
			return Result{IsTLS: true, NeedMore: true}, ErrNeedMore
		}
		take := need - len(s.acc)
		if take > len(seg) {
			take = len(seg)
		}
		if len(s.acc)+take > maxAccumulate {
			s.state, s.res, s.err = stateFailed, Result{}, ErrMalformed
			return s.res, s.err
		}
		if s.acc == nil {
			// One-time warm-up allocation; the buffer is reused
			// by every later feed and by Reset.
			s.acc = make([]byte, 0, maxAccumulate)
		}
		s.acc = append(s.acc, seg[:take]...)
		seg = seg[take:]
	}
}
