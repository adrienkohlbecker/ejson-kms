package mock

import (
	"crypto/rand"
	"fmt"
)

type constReader struct {
	nonce string
}

func (r *constReader) Read(p []byte) (n int, err error) {
	copy(p[:], []byte(r.nonce))
	return len(r.nonce), nil
}

// WithConstRandReader runs the given closure with every call
// to crypto/rand.Reader.Read() returning the same string.
func WithConstRandReader(testNonce string, f func()) {

	original := rand.Reader
	rand.Reader = &constReader{nonce: testNonce}

	f()

	rand.Reader = original

}

type errorReader struct {
	err string
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf(r.err)
}

// WithErrorRandReader runs the given closure with every call
// to crypto/rand.Reader.Read() returnint an error.
func WithErrorRandReader(testError string, f func()) {

	original := rand.Reader
	rand.Reader = &errorReader{err: testError}

	f()

	rand.Reader = original

}
