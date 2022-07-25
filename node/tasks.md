### Remaining GH-499 Tasks:

* Modify `ActorSystemFactory` to send `NewPublicIp` messages in change handler.
* Modify `StreamHandlerPool` to receive `NewPublicIp` and shut down all existing streams.
* Modify `Neighborhood` to receive `NewPublicIp` and Gossip new IP address around
