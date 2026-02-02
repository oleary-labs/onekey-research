package onekey_research

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/unified/adapters"
	"github.com/stretchr/testify/require"

	"testing"
)

func TestBasic(t *testing.T) {

	parties := []party.ID{"deadbeef1", "deadbeef2", "deadbeef3"}
	pl := pool.NewPool(0)

	// Generate threshold keys
	keyGenFunc := cmp.Keygen(curve.Secp256k1{}, parties[0], parties, 2, pl)
	session, err := keyGenFunc(nil)
	require.NoError(t, err)
	_ = session

	// Create chain adapter
	factory := &adapters.AdapterFactory{}
	adapter := factory.NewAdapter("ethereum", adapters.SignatureECDSA)

	testTx := map[string]any{"foo": "bar"}

	config := cmp.EmptyConfig(curve.Secp256k1{})
	// Sign transaction
	digest, _ := adapter.Digest(testTx)
	sigFunc := cmp.Sign(config, parties, digest, pl)
	sigFunc(nil)

	// Encode for blockchain
	// encoded, _ := adapter.Encode(signature)

}
