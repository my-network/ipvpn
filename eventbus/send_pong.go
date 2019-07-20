package eventbus

func SendPong(bus EventBus, sourceModuleName, destinationModuleName string) {
	bus.Publish(TopicPong(destinationModuleName), sourceModuleName)
}
