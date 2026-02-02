package network

import (
	"context"
	"fmt"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// SessionNetwork is a session-scoped network that plugs into the Handler message loop.
// Directed messages use libp2p streams; broadcasts use GossipSub.
type SessionNetwork struct {
	host      *Host
	self      party.ID
	sessionID string

	topic *pubsub.Topic
	sub   *pubsub.Subscription

	incoming chan *protocol.Message // fed by both stream handler and pubsub
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewSessionNetwork creates a session-scoped network.
// It joins a GossipSub topic named after the sessionID and starts forwarding
// both directed (stream) and broadcast (pubsub) messages into a single channel.
func NewSessionNetwork(ctx context.Context, host *Host, sessionID string) (*SessionNetwork, error) {
	topicName := fmt.Sprintf("/threshold/session/%s", sessionID)
	topic, err := host.PubSub().Join(topicName)
	if err != nil {
		return nil, fmt.Errorf("join topic %s: %w", topicName, err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		topic.Close()
		return nil, fmt.Errorf("subscribe topic %s: %w", topicName, err)
	}

	ctx, cancel := context.WithCancel(ctx)

	sn := &SessionNetwork{
		host:      host,
		self:      host.Self(),
		sessionID: sessionID,
		topic:     topic,
		sub:       sub,
		incoming:  make(chan *protocol.Message, 1000),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Forward directed messages from the host's stream handler.
	sn.wg.Add(1)
	go sn.forwardDirected()

	// Forward broadcast messages from GossipSub.
	sn.wg.Add(1)
	go sn.forwardBroadcasts()

	return sn, nil
}

// Send sends a protocol message. Broadcast messages go to GossipSub;
// directed messages open a stream to the target peer.
func (sn *SessionNetwork) Send(msg *protocol.Message) {
	if msg.To == "" {
		// Broadcast via GossipSub.
		data, err := msg.MarshalBinary()
		if err != nil {
			return
		}
		sn.topic.Publish(sn.ctx, data)
	} else {
		// Directed: find the peer and open a stream.
		pid, ok := sn.host.PeerForParty(msg.To)
		if !ok {
			return
		}
		sn.host.SendDirect(sn.ctx, pid, msg)
	}
}

// Next returns the channel that delivers incoming messages (both directed and broadcast).
func (sn *SessionNetwork) Next() <-chan *protocol.Message {
	return sn.incoming
}

// Close unsubscribes from the topic and stops forwarding goroutines.
func (sn *SessionNetwork) Close() {
	sn.cancel()
	sn.sub.Cancel()
	sn.topic.Close()
	sn.wg.Wait()
	close(sn.incoming)
}

// forwardDirected reads from the host's incoming stream channel
// and forwards messages into the session's incoming channel.
func (sn *SessionNetwork) forwardDirected() {
	defer sn.wg.Done()
	for {
		select {
		case <-sn.ctx.Done():
			return
		case msg, ok := <-sn.host.Incoming():
			if !ok {
				return
			}
			select {
			case sn.incoming <- msg:
			case <-sn.ctx.Done():
				return
			}
		}
	}
}

// forwardBroadcasts reads from the GossipSub subscription and forwards
// deserialized messages into the session's incoming channel.
// Messages from self are ignored (GossipSub delivers our own publishes back).
func (sn *SessionNetwork) forwardBroadcasts() {
	defer sn.wg.Done()
	for {
		raw, err := sn.sub.Next(sn.ctx)
		if err != nil {
			return // context cancelled or subscription closed
		}
		// Skip messages from our own peer.
		if raw.ReceivedFrom == sn.host.PeerID() {
			continue
		}
		msg := &protocol.Message{}
		if err := msg.UnmarshalBinary(raw.Data); err != nil {
			continue
		}
		select {
		case sn.incoming <- msg:
		case <-sn.ctx.Done():
			return
		}
	}
}
