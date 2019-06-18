package network

import (
	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/homenet-server/iface"
)

type Path struct {
	Designation iface.Peer
	NextHop     *Router
}

func NewPath(designation iface.Peer, nextHop *Router) *Path {
	return &Path{
		Designation: designation,
		NextHop:     nextHop,
	}
}

func (path *Path) IsValid() bool {
	return !path.NextHop.IsClosed()
}

func (path *Path) Close() error {
	return nil
}

func (path *Path) ServiceRead(serviceID ServiceID, b []byte) error {
	return path.NextHop.MessageRead(serviceID, path.Designation.GetIntAlias(), b)
}

func (path *Path) ServiceWrite(serviceID ServiceID, b []byte) error {
	return path.NextHop.MessageWrite(serviceID, path.Designation.GetIntAlias(), b)
}

type pathReadWriter struct {
	ServiceID ServiceID
	Path      *Path
}

func (path *Path) GetReadWriter(serviceID ServiceID) *pathReadWriter {
	return &pathReadWriter{
		ServiceID: serviceID,
		Path:      path,
	}
}

func (wrapper *pathReadWriter) Read(b []byte) (n int, err error) {
	err = wrapper.Path.ServiceRead(wrapper.ServiceID, b)
	if err != nil {
		err = errors.Wrap(err, wrapper.ServiceID)
	} else {
		n = len(b)
	}
	return
}

func (wrapper *pathReadWriter) Write(b []byte) (n int, err error) {
	err = wrapper.Path.ServiceWrite(wrapper.ServiceID, b)
	if err != nil {
		err = errors.Wrap(err, wrapper.ServiceID)
	} else {
		n = len(b)
	}
	return
}
