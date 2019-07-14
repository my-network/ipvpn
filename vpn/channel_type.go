package vpn

type ChannelType uint8

const (
	ChannelType_undefined = ChannelType(iota)

	ChannelTypeDirect
	ChannelTypeIPFS
	ChannelTypeTunnel

	ChannelType_max

	ChannelTypeAutoRouted
)

var (
	ChannelTypes = []ChannelType{
		ChannelTypeDirect,
		ChannelTypeIPFS,
		ChannelTypeTunnel,
	}
)

func (chType ChannelType) String() string {
	switch chType {
	case ChannelType_undefined:
		return `undefined`
	case ChannelTypeDirect:
		return `direct`
	case ChannelTypeIPFS:
		return `ipfs`
	case ChannelTypeTunnel:
		return `tunnel`
	default:
		return `unknown-type`
	}
}
