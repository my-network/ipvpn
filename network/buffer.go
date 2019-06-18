package network

import (
	"bytes"
	"sync"
)

type buffer struct {
	bytes.Buffer
}

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := &buffer{}
			buf.Grow(4096)
			return buf
		},
	}
)

func NewBuffer() *buffer {
	return bufferPool.Get().(*buffer)
}

func (buf *buffer) Release() {
	buf.Reset()
	bufferPool.Put(buf)
}
