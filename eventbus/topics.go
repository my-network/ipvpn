package eventbus

import (
	"github.com/libp2p/go-libp2p-core/protocol"
)

const (
	TopicFromApplicationClose = `On:Application.Close()`

	TopicFromNetworkSetMyAddrs = `On:Network.SetMyAddrs()`
	TopicFromNetworkSetMyID = `On:Network.SetMyID()`
	TopicFromNetworkSetPSK = `On:Network.SetPSK()`
	TopicFromNetworkSetPrivateKey = `On:Network.SetPrivateKey()`
	TopicFromNetworkReady = `On:Network.Ready()`
	TopicFromNetworkConsiderKnownPeer = `On:Network.ConsiderKnownPeer()`

	TopicToNetworkSetStreamHandler = `Call:Network.SetStreamHandler()`

	topicFromNetworkNewStream = `On:Network.NewStream()`
	topicPing = `Call:module.Ping()`
	topicPong = `Call:module.Pong()`
)

func TopicFromNetworkNewStream(protocolID protocol.ID) string {
	return topicFromNetworkNewStream+`:`+string(protocolID)
}

func TopicPing(moduleName string) string {
	return topicPing+`:`+moduleName
}

func TopicPong(moduleName string) string {
	return topicPong+`:`+moduleName
}