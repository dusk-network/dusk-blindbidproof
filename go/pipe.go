package zkproof

import (
	"bytes"
	"io"
	"io/ioutil"
	"sync"
	"syscall"
)

// NamedPipe holds data for a named pipe.
type NamedPipe struct {
	path  string
	mutex *sync.Mutex
	buf   *bytes.Buffer
}

// NewNamedPipe returns a NamedPipe on the path given.
func NewNamedPipe(path string) NamedPipe {
	np := NamedPipe{path, &sync.Mutex{}, &bytes.Buffer{}}
	syscall.Mkfifo(path, 0644)

	return np
}

// Write writes `len(p)` bytes from `p` to the named pipe.
// It returns the number of bytes written from `p (0 <= n <= len(p))` and any
// error encountered that caused the write to stop early.
//
// This operation locks the `NamedPipe`.
// the calling goroutine blocks until the function's end.
func (np *NamedPipe) Write(p []byte) (n int, err error) {
	np.mutex.Lock()
	defer np.mutex.Unlock()

	return len(p), ioutil.WriteFile(np.path, p, 0644)
}

// Read reads up to `len(p)` bytes  from the named pipe into `p`.
// It returns the number of bytes read `(0 <= n <= len(p))` and any error
// encountered.
//
// Read should be used only when a `io.Reader` interface is needed: since a
// direct reading operation to the named pipe is blocking, the NamedPipe uses
// an internal buffer wrapped around `ReadAll` to handles multiple reading
// calls without accessing every call to the underlying named pipe.
//
// Therefore, `ReadAll` should be used when `io.Reader` interface is not
// necesssary.
//
// This operation locks the `NamedPipe`.
// the calling goroutine blocks until the function's end.
func (np *NamedPipe) Read(p []byte) (n int, err error) {
	if np.buf.Len() == 0 {
		bytes, err := np.ReadAll()
		if err != nil {
			return 0, err
		}
		np.buf.Write(bytes)
	}

	n, err = np.buf.Read(p)
	if err == io.EOF || n < len(p) {
		np.buf.Reset()
		return n, io.EOF
	}
	return n, err
}

// ReadAll reads from the named pipe until an error or EOF and returns the data
// it read.
// A successful call returns `err == nil`, not `err == EOF`.
// Because ReadAll is defined to read from src until EOF, it does not treat an
// EOF from Read as an error to be reported.
//
// This operation locks the `NamedPipe`.
// the calling goroutine blocks until the function's end.
func (np *NamedPipe) ReadAll() ([]byte, error) {
	np.mutex.Lock()
	defer np.mutex.Unlock()

	return ioutil.ReadFile(np.path)
}
