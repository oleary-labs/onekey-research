# Quick Reference Guide
## Distributed Key Management with LuxFi Threshold Library

**Last Updated**: February 2026  
**Library Version**: v1.0.1+  
**Repository**: https://github.com/luxfi/threshold

---

## Installation

```bash
go get github.com/luxfi/threshold@v1.0.1
```

---

## Protocol Selection

| Use Case | Protocol | Reason |
|----------|----------|--------|
| Ethereum & EVM chains | CMP | Identifiable aborts, ECDSA support, production proven |
| Dynamic node management | LSS | Zero-downtime resharing |
| Two-party wallets | Doerner | Optimized for 2-of-2, lowest latency |

**Note**: Initial version targets Ethereum-compatible chains only (Ethereum, Polygon, Arbitrum, Optimism, Base, BSC, Avalanche C-Chain, etc.)

---

## Supported Networks

### Ethereum Virtual Machine (EVM) Compatible Chains

| Network | Chain ID | Signature | Native Currency |
|---------|----------|-----------|-----------------|
| Ethereum Mainnet | 1 | ECDSA (secp256k1) | ETH |
| Polygon | 137 | ECDSA (secp256k1) | MATIC |
| Arbitrum One | 42161 | ECDSA (secp256k1) | ETH |
| Optimism | 10 | ECDSA (secp256k1) | ETH |
| Base | 8453 | ECDSA (secp256k1) | ETH |
| Avalanche C-Chain | 43114 | ECDSA (secp256k1) | AVAX |
| BNB Smart Chain | 56 | ECDSA (secp256k1) | BNB |

**All EVM chains use the same address** - derived deterministically from the public key using keccak256 hashing.

---

## Basic Usage Examples

### 1. Key Generation (CMP Protocol)

```go
import (
    "github.com/luxfi/threshold/protocols/cmp"
    "github.com/luxfi/threshold/pkg/math/curve"
    "github.com/luxfi/threshold/pkg/party"
    "github.com/luxfi/threshold/pkg/pool"
)

// Setup
selfID := party.ID("node1")
parties := []party.ID{"node1", "node2", "node3", "node4", "node5"}
threshold := 3 // 3-of-5
workerPool := pool.NewPool(runtime.NumCPU())
defer workerPool.TearDown()

// Generate threshold keys
configs := cmp.Keygen(
    curve.Secp256k1{},
    selfID,
    parties,
    threshold,
    workerPool,
)

// Get public key
publicKey := configs[selfID].PublicKey()
```

### 2. Signing Transactions

```go
// Prepare transaction
txHash := crypto.Keccak256Hash(transaction.Bytes())

// Select signers (any 3 of 5)
signers := []party.ID{"node1", "node3", "node5"}

// Sign
signature := cmp.Sign(
    configs[selfID],
    signers,
    txHash[:],
    workerPool,
)
```

### 3. Multi-Chain EVM Support

```go
import "github.com/luxfi/threshold/protocols/unified/adapters"

// Create EVM adapter (works for all Ethereum-compatible chains)
evmAdapter := adapters.NewEthereumAdapter(adapters.SignatureECDSA)

// Get Ethereum address from public key
// Same address works across ALL EVM chains
ethereumAddress := evmAdapter.GetAddress(publicKey.Bytes())

// Sign for different EVM chains (same signature algorithm, different chain IDs)
func signForChain(chainID *big.Int, tx Transaction) {
    // Set chain ID for EIP-155 replay protection
    tx.ChainID = chainID
    
    // Generate digest and sign
    digest, _ := evmAdapter.Digest(tx)
    signature := cmp.Sign(config, signers, digest, pool)
    
    return evmAdapter.EncodeTransaction(tx, signature, chainID)
}

// Examples for different chains
ethereumTx := signForChain(big.NewInt(1), tx)      // Ethereum
polygonTx := signForChain(big.NewInt(137), tx)     // Polygon
arbitrumTx := signForChain(big.NewInt(42161), tx)  // Arbitrum
optimismTx := signForChain(big.NewInt(10), tx)     // Optimism
baseTx := signForChain(big.NewInt(8453), tx)       // Base
```

### 4. Dynamic Resharing (LSS)

```go
import "github.com/luxfi/threshold/protocols/lss"

// Add new nodes to existing group
newParties := []party.ID{"node1", "node2", "node3", "node4", "node5", "node6", "node7"}
newConfigs := lss.Reshare(
    configs,
    newParties,
    4, // new threshold: 4-of-7
    workerPool,
)

// Remove compromised nodes
remainingParties := []party.ID{"node1", "node2", "node4", "node5"}
reducedConfigs := lss.Reshare(
    configs,
    remainingParties,
    3, // maintain 3-of-4
    workerPool,
)
```

### 5. EIP-1559 Transaction Support

```go
// Modern Ethereum transactions with dynamic fee market
type EIP1559Transaction struct {
    ChainID              *big.Int
    Nonce                uint64
    MaxPriorityFeePerGas *big.Int  // Tip to miners
    MaxFeePerGas         *big.Int  // Maximum total fee
    GasLimit             uint64
    To                   common.Address
    Value                *big.Int
    Data                 []byte
}

// Sign EIP-1559 transaction
digest, _ := evmAdapter.Digest(eip1559Tx)
signature := cmp.Sign(config, signers, digest, pool)
signedTx := evmAdapter.EncodeTransaction(eip1559Tx, signature, chainID)
```

### 6. Smart Contract Wallets (EIP-1271)

```solidity
// Threshold wallet implementing EIP-1271
contract ThresholdWallet {
    bytes32 public publicKeyHash;
    
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4) {
        if (verifyThresholdSignature(hash, signature)) {
            return 0x1626ba7e; // EIP-1271 magic value
        }
        return 0xffffffff;
    }
}
```

---

## Smart Contract Integration

### Node Registration

```solidity
// Register as a key management node
function registerNode(
    string calldata endpoint,
    bytes32 publicKeyHash,
    NodeType nodeType,
    bytes calldata metadata
) external {
    nodes[msg.sender] = NodeRegistration({
        nodeAddress: msg.sender,
        endpoint: endpoint,
        publicKeyHash: publicKeyHash,
        nodeType: nodeType,
        registrationTime: block.timestamp,
        status: NodeStatus.ACTIVE,
        reputation: 0,
        metadata: metadata
    });
    
    emit NodeRegistered(msg.sender, block.timestamp);
}
```

### Group Creation

```solidity
// Wallet creates key management group
function createGroup(
    address[] calldata selectedNodes,
    uint8 threshold,
    uint8 totalShares
) external returns (uint256 groupId) {
    require(threshold <= totalShares, "Invalid threshold");
    require(selectedNodes.length == totalShares, "Node count mismatch");
    
    groupId = nextGroupId++;
    groups[groupId] = GroupConfiguration({
        groupId: groupId,
        walletOwner: msg.sender,
        selectedNodes: selectedNodes,
        threshold: threshold,
        totalShares: totalShares,
        creationTime: block.timestamp,
        status: GroupStatus.PENDING,
        publicKeyHash: bytes32(0)
    });
    
    emit GroupCreated(groupId, msg.sender, selectedNodes);
}
```

### Recording Public Key

```solidity
// Node records generated public key
function recordPublicKey(
    uint256 groupId,
    bytes32 publicKeyHash
) external {
    require(isNodeInGroup(groupId, msg.sender), "Not in group");
    require(groups[groupId].status == GroupStatus.PENDING, "Invalid status");
    
    groups[groupId].publicKeyHash = publicKeyHash;
    groups[groupId].status = GroupStatus.ACTIVE;
    
    emit KeyGenerated(groupId, publicKeyHash);
}
```

---

## Node API Endpoints

### HTTP REST API

```go
// POST /v1/dkg/participate
type DKGParticipateRequest struct {
    GroupID    uint64      `json:"group_id"`
    Parties    []party.ID  `json:"parties"`
    Threshold  int         `json:"threshold"`
}

// POST /v1/sign/request
type SignRequest struct {
    GroupID    uint64      `json:"group_id"`
    Digest     []byte      `json:"digest"`
    Signers    []party.ID  `json:"signers"`
}

// POST /v1/reshare/initiate
type ReshareRequest struct {
    GroupID      uint64      `json:"group_id"`
    NewParties   []party.ID  `json:"new_parties"`
    NewThreshold int         `json:"new_threshold"`
}

// GET /v1/health
type HealthResponse struct {
    Status      string    `json:"status"`
    Version     string    `json:"version"`
    Uptime      uint64    `json:"uptime"`
    ActiveGroups int      `json:"active_groups"`
}
```

---

## Performance Benchmarks

### Key Generation Latency

| Threshold | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|-----------|--------|--------|---------|----------|
| CMP       | 12ms   | 28ms   | 45ms    | 82ms     |
| FROST     | 8ms    | 18ms   | 30ms    | 55ms     |

### Signing Latency

| Protocol | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|----------|--------|--------|---------|----------|
| CMP      | 8ms    | 15ms   | 24ms    | 40ms     |
| FROST    | 4ms    | 8ms    | 12ms    | 20ms     |
| Doerner  | 5ms    | N/A    | N/A     | N/A      |

### Resharing Latency (LSS)

| Threshold | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|-----------|--------|--------|---------|----------|
| LSS       | 20ms   | 35ms   | 52ms    | 75ms     |

---

## Security Checklist

### Node Operators

- [ ] Store key shares in HSM or secure enclave
- [ ] Use TLS 1.3+ for all network communication
- [ ] Implement rate limiting on API endpoints
- [ ] Enable 24/7 monitoring and alerting
- [ ] Maintain offline backup of node configuration
- [ ] Regular security audits and penetration testing
- [ ] Isolate key management processes in secure environment

### Wallet Developers

- [ ] Verify all signatures before broadcasting transactions
- [ ] Implement retry logic for network failures
- [ ] Use time-locks for recovery operations (minimum 7 days)
- [ ] Enable multi-factor authentication for recovery
- [ ] Store group configuration securely
- [ ] Implement veto mechanism for fraudulent recovery attempts
- [ ] Provide clear UI for threshold status

### Smart Contract Deployment

- [ ] Multiple independent security audits completed
- [ ] Formal verification of critical functions
- [ ] Bug bounty program active
- [ ] Gradual rollout with limits
- [ ] Emergency pause mechanism implemented
- [ ] Upgrade path clearly defined
- [ ] Gas optimization verified

---

## Common Patterns

### Pattern 1: High-Availability Signing

```go
// Pre-generate signing material for instant signing
presigningCache := make(chan *cmp.PresigningMaterial, 100)

go func() {
    for {
        presigning := cmp.Presign(config, signers, pool)
        presigningCache <- presigning
    }
}()

// Use cached presigning for low-latency
presigning := <-presigningCache
signature := cmp.SignWithPresigning(config, signers, digest, presigning)
```

### Pattern 2: Fault Detection with Identifiable Aborts

```go
// Detect malicious parties during signing
signature, abortingParty := cmp.SignWithAbortIdentification(
    config,
    signers,
    digest,
    pool,
)

if abortingParty != nil {
    // Report to blockchain and retry
    blockchain.ReportMaliciousNode(groupID, *abortingParty)
    newSigners := excludeParty(signers, *abortingParty)
    signature, _ = cmp.Sign(config, newSigners, digest, pool)
}
```

### Pattern 3: Automated Node Replacement

```go
healthMonitor := NewNodeHealthMonitor(nodes, 30*time.Second)

healthMonitor.OnHealthChange(func(healthyNodes []party.ID) {
    if len(healthyNodes) <= threshold + 2 {
        // Recruit and add new nodes
        newNodes := recruitNewNodes(3)
        allNodes := append(healthyNodes, newNodes...)
        newConfigs := lss.Reshare(configs, allNodes, threshold, pool)
        
        // Update blockchain
        blockchain.UpdateGroupNodes(groupID, allNodes)
    }
})
```

---

## Troubleshooting

### Issue: DKG Ceremony Fails

**Possible Causes**:
- Network timeout between nodes
- Incompatible protocol versions
- Insufficient worker pool size

**Solutions**:
```go
// Increase timeout
context.WithTimeout(ctx, 60*time.Second)

// Verify protocol version
require.Equal(t, "v1.0.1", version)

// Increase pool size
pool := pool.NewPool(runtime.NumCPU() * 2)
```

### Issue: Signature Verification Fails

**Possible Causes**:
- Wrong curve used for verification
- Incorrect digest format
- Chain-specific encoding issues

**Solutions**:
```go
// Verify curve matches
require.Equal(t, curve.Secp256k1{}, config.Curve())

// Use chain adapter for digest
adapter := adapters.NewEthereumAdapter(adapters.SignatureECDSA)
digest, _ := adapter.Digest(tx)

// Verify signature before broadcasting
if !adapter.Verify(publicKey, digest, signature) {
    return errors.New("invalid signature")
}
```

### Issue: Resharing Takes Too Long

**Possible Causes**:
- Too many parties in new configuration
- Network latency
- Insufficient computational resources

**Solutions**:
```go
// Limit party count
maxParties := 15

// Use faster networking
grpcConn, _ := grpc.Dial(addr, grpc.WithKeepalive())

// Increase worker pool
pool := pool.NewPool(runtime.NumCPU() * 2)
```

---

## Additional Resources

- **LuxFi Threshold Library**: https://github.com/luxfi/threshold
- **Production Readiness Report**: https://github.com/luxfi/threshold/blob/main/PRODUCTION_READY.md
- **API Documentation**: https://github.com/luxfi/threshold/blob/main/docs/api.md
- **Example Implementations**: https://github.com/luxfi/threshold/tree/main/example

---

## Support

For issues with the LuxFi library, please file an issue at:
https://github.com/luxfi/threshold/issues
