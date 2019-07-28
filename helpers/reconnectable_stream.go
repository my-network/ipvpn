package helpers

import (
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/xaionaro-go/errors"
)

type Stream = network.Stream

type ReconnectableStream struct {
	Stream
	logger  Logger
	newFunc func() (Stream, error)
}

func NewReconnectableStream(logger Logger, newFunc func() (Stream, error)) *ReconnectableStream {
	stream := &ReconnectableStream{
		logger:  logger,
		newFunc: newFunc,
	}

	return stream
}

func (stream *ReconnectableStream) Connect() {
	for i := 0; i < 10; i++ {
		streamRaw, err := stream.newFunc()
		if err != nil {
			stream.logger.Debugf(`unable to connect: %v`, errors.Wrap(err))
			continue
		}

		stream.Stream = streamRaw
		return
	}
}
