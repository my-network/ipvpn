package vpn

type Peer struct {
	VPN      *VPN
	Stream   Stream
	IntAlias IntAlias
}

func (peer *Peer) Close() error {
	return peer.Stream.Close()
}

func (peer *Peer) Start() error {
	return nil
}
