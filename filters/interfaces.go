package filters

import (
	"io"
)

type Filter interface {
	WrapReader(io.Reader) io.Reader
	WrapWriter(io.Writer) io.Writer
}
