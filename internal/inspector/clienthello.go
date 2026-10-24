package inspector

// TLS wire constants used by the ClientHello parser.
const (
	contentTypeHandshake     = 0x16
	handshakeTypeClientHello = 0x01
	recordHeaderLen          = 5
	handshakeHeaderLen       = 4
	versionMajor             = 0x03 // SSLv3 and every TLS version share major 3

	extServerName = 0x0000
	extALPN       = 0x0010
	extECH        = 0xfe0d
	extECHLegacy  = 0xff0d

	// maxRecordLen is the largest record payload the inspector is willing
	// to reassemble (the per-stream buffer minus the record header).
	maxRecordLen = maxAccumulate - recordHeaderLen
)

// needBytes returns how many bytes of prefix b are required before the
// ClientHello can be fully parsed, validating every header byte seen so
// far. It returns ErrNotTLS or ErrMalformed as soon as the prefix violates
// the protocol, so a bad header is rejected without waiting for payload.
// needBytes never panics regardless of input length.
func needBytes(b []byte) (int, error) {
	if len(b) == 0 {
		return recordHeaderLen, nil
	}
	if b[0] != contentTypeHandshake {
		return 0, ErrNotTLS
	}
	if len(b) < recordHeaderLen {
		return recordHeaderLen, nil
	}
	if b[1] != versionMajor {
		return 0, ErrMalformed
	}
	recLen := int(b[3])<<8 | int(b[4])
	// A handshake record with an empty payload, or one whose payload
	// cannot fit the per-stream reassembly buffer.
	if recLen == 0 || recLen > maxRecordLen {
		return 0, ErrMalformed
	}
	if len(b) < recordHeaderLen+handshakeHeaderLen {
		return recordHeaderLen + handshakeHeaderLen, nil
	}
	if b[5] != handshakeTypeClientHello {
		return 0, ErrNotTLS
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if handshakeHeaderLen+hsLen > recLen {
		// The ClientHello would span multiple records; a real
		// ClientHello always fits one record at our 8 KB cap.
		return 0, ErrMalformed
	}
	return recordHeaderLen + handshakeHeaderLen + hsLen, nil
}

// parseClientHello parses a ClientHello from b, which may be a caller-owned
// segment (fast path) or the stream reassembly buffer. SNI and ALPN in the
// returned Result are subslices of b — nothing is copied. It returns
// ErrNeedMore when b is a valid but incomplete prefix, ErrNotTLS or
// ErrMalformed when the bytes cannot be a ClientHello. parseClientHello
// never panics regardless of input.
func parseClientHello(b []byte) (Result, error) {
	need, err := needBytes(b)
	if err != nil {
		return Result{}, err
	}
	if len(b) < need {
		return Result{}, ErrNeedMore
	}
	res := Result{IsTLS: true}

	// ClientHello body (TLS 1.2 and 1.3 share this legacy layout):
	//   legacy_version[2] random[32]
	//   session_id<1..32>            (1-byte length)
	//   cipher_suites<2..2^16-2>     (2-byte length, 2 bytes per suite)
	//   compression_methods<1..256>  (1-byte length)
	//   extensions<0..2^16-1>        (2-byte length, optional)
	body := b[recordHeaderLen+handshakeHeaderLen : need]
	const fixedLen = 2 + 32 // legacy_version + random
	if len(body) < fixedLen+1 {
		return Result{}, ErrMalformed
	}
	off := fixedLen

	sidLen := int(body[off])
	off++
	if off+sidLen+2 > len(body) { // session_id + cipher_suites length field
		return Result{}, ErrMalformed
	}
	off += sidLen

	csLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if csLen < 2 || csLen%2 != 0 || off+csLen+1 > len(body) {
		return Result{}, ErrMalformed
	}
	off += csLen

	compLen := int(body[off])
	off++
	if compLen < 1 || off+compLen > len(body) {
		return Result{}, ErrMalformed
	}
	off += compLen

	if off == len(body) {
		// No extensions block at all (ancient SSLv3/TLS 1.0 clients):
		// a valid ClientHello without SNI.
		return res, nil
	}

	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if off+extLen > len(body) {
		// Extension block declared longer than the message.
		return Result{}, ErrMalformed
	}
	extEnd := off + extLen
	for off+4 <= extEnd {
		etype := int(body[off])<<8 | int(body[off+1])
		elen := int(body[off+2])<<8 | int(body[off+3])
		off += 4
		if off+elen > extEnd {
			// Single extension declared longer than the block.
			return Result{}, ErrMalformed
		}
		switch etype {
		case extServerName:
			if !res.SNIFound {
				if sni, ok := parseSNIExt(body[off : off+elen]); ok {
					res.SNI, res.SNIFound = sni, true
				}
			}
		case extALPN:
			if res.ALPN == nil {
				res.ALPN, _ = parseALPNExt(body[off : off+elen])
			}
		case extECH, extECHLegacy:
			res.ECH = true
		}
		off += elen
	}
	if off != extEnd {
		// Trailing bytes inside the extensions block that do not form
		// a complete extension header.
		return Result{}, ErrMalformed
	}
	return res, nil
}

// parseSNIExt extracts the first host_name (name_type 0) entry from a
// server_name extension payload and returns it as a subslice of d.
// Malformed or empty lists report false; the ClientHello itself stays
// valid.
func parseSNIExt(d []byte) ([]byte, bool) {
	// ServerNameList: uint16 list length, then entries of
	// (uint8 name_type, uint16 name length, opaque name).
	if len(d) < 2 {
		return nil, false
	}
	listLen := int(d[0])<<8 | int(d[1])
	limit := 2 + listLen
	if limit > len(d) {
		return nil, false
	}
	for off := 2; off+3 <= limit; {
		nameType := d[off]
		nameLen := int(d[off+1])<<8 | int(d[off+2])
		off += 3
		if off+nameLen > limit {
			return nil, false
		}
		if nameType == 0 && nameLen > 0 {
			return d[off : off+nameLen], true
		}
		off += nameLen
	}
	return nil, false
}

// parseALPNExt extracts the first protocol name from an ALPN extension
// payload as a subslice of d. RFC 7301: uint16 list length, then entries
// of (uint8 length, opaque name).
func parseALPNExt(d []byte) ([]byte, bool) {
	if len(d) < 3 {
		return nil, false
	}
	listLen := int(d[0])<<8 | int(d[1])
	limit := 2 + listLen
	if limit > len(d) || limit < 3 {
		return nil, false
	}
	nameLen := int(d[2])
	if 3+nameLen > limit || nameLen == 0 {
		return nil, false
	}
	return d[3 : 3+nameLen], true
}
