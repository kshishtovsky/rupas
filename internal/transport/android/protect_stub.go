//go:build !unix

package android

// Windows dev-host stub: the protect fd-passing protocol only exists on
// Android/Linux. `go build ./...` stays green; the relay on Windows simply
// gets no protect_path (tunnel egress is never exercised there).
func startProtector(protect ProtectFunc, dir string, logFn func(string)) (path string, stop func(), err error) {
	return "", nil, nil
}
