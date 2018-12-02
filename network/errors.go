package network

import (
	"github.com/xaionaro-go/errors"
)

var (
	ErrMyselfNotFound = errors.New("Not found myself in the peers list")
	ErrNotReady       = errors.New("Not ready")
)
