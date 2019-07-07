package vpn

type channelType uint8

const (
	channelType_undefined = channelType(iota)

	channelTypeDirect
	channelTypeIPFS
	channelTypeTunnel

	channelType_max

	channelTypeAutoRouted
)

var (
	channelTypes = []channelType{
		channelTypeDirect,
		channelTypeIPFS,
		channelTypeTunnel,
	}
)

func (chType channelType) String() string {
	switch chType {
	case channelType_undefined:
		return `undefined`
	case channelTypeDirect:
		return `direct`
	case channelTypeIPFS:
		return `ipfs`
	case channelTypeTunnel:
		return `tunnel`
	default:
		return `unknown-type`
	}
}
