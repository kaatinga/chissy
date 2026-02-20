package chissy

import (
	"bytes"
	"os"
)

type filteringWriter struct {
	filters [][]byte
}

func newFilteringWriter() *filteringWriter {
	return &filteringWriter{
		filters: [][]byte{
			[]byte("TLS handshake error from"),
		},
	}
}

func (f *filteringWriter) Write(p []byte) (n int, err error) {
	for _, filter := range f.filters {
		if bytes.Contains(p, filter) {
			return len(p), nil
		}
	}

	return os.Stderr.Write(p)
}
