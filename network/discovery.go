package network

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/luxfi/threshold/pkg/party"
)

// mdnsServiceTag is used as the mDNS service tag.
// The party.ID is appended so peers can identify each other.
const mdnsServiceTag = "threshold-mpc"

// discoveryNotifee is called by mDNS when a peer is found.
type discoveryNotifee struct {
	host *Host
	mu   sync.Mutex
}

// HandlePeerFound is called when a new peer is discovered via mDNS.
// The peer advertises its party.ID in the service tag.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()

	h := n.host.LibP2PHost()
	if pi.ID == h.ID() {
		return // skip self
	}

	// Connect to the peer if not already connected.
	if err := h.Connect(context.Background(), pi); err != nil {
		return
	}
}

// SetupMDNS starts mDNS discovery on the local network.
// Each host advertises under "threshold-mpc/<partyID>" so peers can map
// party.ID -> peer.ID when they discover each other.
func SetupMDNS(host *Host) error {
	n := &discoveryNotifee{host: host}
	tag := fmt.Sprintf("%s/%s", mdnsServiceTag, string(host.Self()))
	svc := mdns.NewMdnsService(host.LibP2PHost(), tag, n)
	return svc.Start()
}

// DiscoverMDNSPeers discovers all peers advertising under "threshold-mpc/*"
// and populates the host's party.ID <-> peer.ID mapping.
// It scans for the given party IDs and returns once all are found or the
// context is cancelled.
func DiscoverMDNSPeers(ctx context.Context, host *Host, partyIDs []party.ID) error {
	// For each party we need to find, start a listener on their service tag.
	var wg sync.WaitGroup
	for _, pid := range partyIDs {
		if pid == host.Self() {
			continue
		}
		wg.Add(1)
		go func(target party.ID) {
			defer wg.Done()
			tag := fmt.Sprintf("%s/%s", mdnsServiceTag, string(target))
			n := &mappingNotifee{host: host, targetParty: target}
			svc := mdns.NewMdnsService(host.LibP2PHost(), tag, n)
			svc.Start()

			// Wait until the peer is found or context expires.
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, ok := host.PeerForParty(target); ok {
						return
					}
				}
			}
		}(pid)
	}
	wg.Wait()
	return ctx.Err()
}

// mappingNotifee connects to discovered peers and registers the party mapping.
type mappingNotifee struct {
	host        *Host
	targetParty party.ID
	mu          sync.Mutex
}

func (n *mappingNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()

	h := n.host.LibP2PHost()
	if pi.ID == h.ID() {
		return
	}
	if err := h.Connect(context.Background(), pi); err != nil {
		return
	}
	n.host.RegisterPeer(n.targetParty, pi.ID)
}

// SetupRendezvous starts a DHT-based rendezvous discovery.
// Peers register under the given namespace (typically sessionID) and advertise
// their party.ID in the registration metadata.
func SetupRendezvous(ctx context.Context, host *Host, namespace string, bootstrapPeers []peer.AddrInfo) error {
	// Connect to bootstrap peers.
	for _, bp := range bootstrapPeers {
		if err := host.LibP2PHost().Connect(ctx, bp); err != nil {
			return fmt.Errorf("connect bootstrap %s: %w", bp.ID, err)
		}
	}

	// Create a DHT in client mode.
	kdht, err := dht.New(ctx, host.LibP2PHost(), dht.Mode(dht.ModeClient))
	if err != nil {
		return fmt.Errorf("new dht: %w", err)
	}
	if err := kdht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap dht: %w", err)
	}

	rd := drouting.NewRoutingDiscovery(kdht)

	// Advertise under "namespace/partyID".
	advNS := fmt.Sprintf("%s/%s", namespace, string(host.Self()))
	dutil.Advertise(ctx, rd, advNS)

	return nil
}

// DiscoverRendezvousPeers finds all peers registered under the namespace
// and builds the party.ID -> peer.ID mapping.
func DiscoverRendezvousPeers(ctx context.Context, host *Host, namespace string, partyIDs []party.ID, bootstrapPeers []peer.AddrInfo) error {
	// Connect to bootstrap peers.
	for _, bp := range bootstrapPeers {
		host.LibP2PHost().Connect(ctx, bp)
	}

	kdht, err := dht.New(ctx, host.LibP2PHost(), dht.Mode(dht.ModeClient))
	if err != nil {
		return fmt.Errorf("new dht: %w", err)
	}
	if err := kdht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap dht: %w", err)
	}

	rd := drouting.NewRoutingDiscovery(kdht)

	// For each party, search under their namespace.
	var wg sync.WaitGroup
	for _, pid := range partyIDs {
		if pid == host.Self() {
			continue
		}
		wg.Add(1)
		go func(target party.ID) {
			defer wg.Done()
			ns := fmt.Sprintf("%s/%s", namespace, string(target))
			peerCh, err := rd.FindPeers(ctx, ns)
			if err != nil {
				return
			}
			for pi := range peerCh {
				if pi.ID == host.LibP2PHost().ID() {
					continue
				}
				if err := host.LibP2PHost().Connect(ctx, pi); err != nil {
					continue
				}
				host.RegisterPeer(target, pi.ID)
				return
			}
		}(pid)
	}
	wg.Wait()
	return ctx.Err()
}

// ConnectDirectly connects two hosts directly and registers their party mappings.
// Useful for testing and scenarios where peer addresses are already known.
func ConnectDirectly(ctx context.Context, a, b *Host) error {
	bInfo := peer.AddrInfo{
		ID:    b.PeerID(),
		Addrs: b.LibP2PHost().Addrs(),
	}
	if err := a.LibP2PHost().Connect(ctx, bInfo); err != nil {
		return fmt.Errorf("connect %s -> %s: %w", a.Self(), b.Self(), err)
	}
	a.RegisterPeer(b.Self(), b.PeerID())
	b.RegisterPeer(a.Self(), a.PeerID())
	return nil
}

// WaitForPeers blocks until all expected party.IDs are registered or context expires.
func WaitForPeers(ctx context.Context, host *Host, partyIDs []party.ID) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			var missing []string
			for _, pid := range partyIDs {
				if pid == host.Self() {
					continue
				}
				if _, ok := host.PeerForParty(pid); !ok {
					missing = append(missing, string(pid))
				}
			}
			return fmt.Errorf("timed out waiting for peers: missing [%s]", strings.Join(missing, ", "))
		case <-ticker.C:
			allFound := true
			for _, pid := range partyIDs {
				if pid == host.Self() {
					continue
				}
				if _, ok := host.PeerForParty(pid); !ok {
					allFound = false
					break
				}
			}
			if allFound {
				return nil
			}
		}
	}
}
