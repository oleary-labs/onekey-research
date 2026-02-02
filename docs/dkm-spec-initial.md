# Distributed Key Management System Specification
## Blockchain-Based Discovery and Coordination Layer

**Version:** 1.0  
**Date:** February 2026  
**Purpose:** Cryptocurrency wallet key management with distributed trust

---

## 1. System Overview

### 1.1 Architecture
The system consists of three primary layers:

1. **Blockchain Layer**: Smart contract-based registry and coordination
2. **Key Management Node Network**: Independent operators providing key share custody using [LuxFi Threshold Library](https://github.com/luxfi/threshold)
3. **Client Applications**: Wallet applications that consume key management services

**Key Technology**: This system leverages the production-ready LuxFi threshold library (v1.0.1+), which provides:
- **Multiple Protocols**: CMP (CGGMP21), FROST, LSS, Doerner
- **20+ Blockchain Support**: Native adapters for Bitcoin, Ethereum, XRPL, Solana, TON, Cardano, and more
- **Post-Quantum Security**: Ringtail lattice-based signatures
- **Production Performance**: Sub-25ms signing, 12-82ms key generation
- **100% Test Coverage**: Zero skipped tests, extensively validated

### 1.2 Core Principles
- **Decentralized Trust**: No single entity controls user keys
- **Threshold Cryptography**: Keys are split using threshold secret sharing (m-of-n)
- **Blockchain Discovery**: Smart contracts facilitate node discovery and group formation
- **Recovery-Focused**: System prioritizes key recovery with LSS dynamic resharing
- **Operator Independence**: Nodes are independently operated and may be public or permissioned
- **Multi-Chain Native**: Single threshold setup supports 20+ blockchains

---

## 2. System Components

### 2.1 Key Management Nodes

#### 2.1.1 Node Types
- **Public Nodes**: Automatically accept all participation requests
- **Permissioned Nodes**: Require operator approval for group participation

#### 2.1.2 Node Registration
Nodes register on-chain with the following information:
```solidity
struct NodeRegistration {
    address nodeAddress;        // Ethereum address of the node
    string endpoint;            // API endpoint (URL or onion address)
    bytes32 publicKeyHash;      // Hash of node's communication public key
    NodeType nodeType;          // PUBLIC or PERMISSIONED
    uint256 registrationTime;   // Timestamp of registration
    NodeStatus status;          // ACTIVE, SUSPENDED, DEREGISTERED
    uint256 reputation;         // Reputation score (optional)
    bytes metadata;             // Additional metadata (certifications, etc.)
}
```

#### 2.1.3 Node Responsibilities
- Maintain high availability (recommended 99%+ uptime)
- Securely store key shares in hardware security modules (HSM) or secure enclaves
- Respond to threshold signing requests
- Participate in key recovery operations
- Maintain secure communication channels with group members

### 2.2 Wallet Applications (Clients)

#### 2.2.1 Client Capabilities
- Query available nodes from blockchain registry
- Form key management groups by selecting nodes
- Initiate distributed key generation (DKG) ceremonies
- Request threshold signatures for transactions
- Trigger key recovery procedures

#### 2.2.2 Group Formation Parameters
```solidity
struct GroupConfiguration {
    uint256 groupId;            // Unique identifier
    address walletOwner;        // Owner's address
    address[] selectedNodes;    // Array of chosen node addresses
    uint8 threshold;            // Minimum signatures required (m)
    uint8 totalShares;          // Total shares distributed (n)
    uint256 creationTime;       // When group was formed
    GroupStatus status;         // PENDING, ACTIVE, RECOVERING, DISSOLVED
    bytes32 publicKeyHash;      // Hash of the generated wallet public key
}
```

### 2.3 Blockchain Smart Contracts

#### 2.3.1 Node Registry Contract
**Purpose**: Track available key management nodes

**Functions**:
- `registerNode(endpoint, publicKey, nodeType, metadata)`: Register a new node
- `updateNodeStatus(status)`: Update node availability
- `deregisterNode()`: Remove node from registry
- `getActiveNodes(nodeType)`: Query available nodes by type
- `getNodeInfo(nodeAddress)`: Retrieve node details

#### 2.3.2 Group Coordination Contract
**Purpose**: Manage wallet key management groups

**Functions**:
- `createGroup(nodeAddresses[], threshold, totalShares)`: Form new group
- `confirmParticipation(groupId)`: Node confirms participation (for permissioned nodes)
- `recordPublicKey(groupId, publicKeyHash)`: Store generated wallet public key
- `initiateRecovery(groupId, proof)`: Start key recovery process
- `updateGroupStatus(groupId, status)`: Change group state
- `dissolveGroup(groupId)`: Terminate group

#### 2.3.3 Audit Log Contract
**Purpose**: Immutable record of key management operations

**Events**:
- `NodeRegistered(address nodeAddress, uint256 timestamp)`
- `GroupCreated(uint256 groupId, address walletOwner, address[] nodes)`
- `KeyGenerated(uint256 groupId, bytes32 publicKeyHash)`
- `SigningRequested(uint256 groupId, bytes32 txHash, uint256 timestamp)`
- `RecoveryInitiated(uint256 groupId, address initiator, uint256 timestamp)`
- `RecoveryCompleted(uint256 groupId, uint256 timestamp)`

---

## 3. Cryptographic Protocols

**Implementation**: [LuxFi Threshold Library](https://github.com/luxfi/threshold) v1.0.1+

### 3.1 Distributed Key Generation (DKG)

#### 3.1.1 Protocol Selection
The system uses the **LuxFi threshold library** which provides multiple battle-tested protocols:

**Primary Protocols**:
- **CMP (CGGMP21)**: ECDSA with identifiable aborts, 4-round online signing, 7-round presigning (~15ms signing)
- **FROST**: Schnorr/EdDSA with BIP-340 Taproot compatibility, 2-round signing (~8ms signing)
- **LSS**: Dynamic resharing with automated fault tolerance and state rollback (~35ms resharing)
- **Doerner**: Optimized 2-of-2 ECDSA for two-party scenarios (~5ms signing)

**Supported Curves**:
- secp256k1 (Bitcoin, Ethereum, XRPL)
- Ed25519 (Solana, TON, Cardano)
- BIP-340 Schnorr (Bitcoin Taproot)

**Post-Quantum Option**:
- Ringtail lattice-based signatures (128/192/256-bit security levels)

#### 3.1.2 DKG Ceremony Flow

**Using CMP Protocol** (Recommended for ECDSA-based chains):
```go
import "github.com/luxfi/threshold/protocols/cmp"

// 1. Initiation: Wallet application creates group on-chain
groupID := blockchain.CreateGroup(selectedNodes, threshold, totalShares)

// 2. Node Confirmation: Selected nodes acknowledge participation
for _, node := range selectedNodes {
    node.ConfirmParticipation(groupID)
}

// 3. Distributed Key Generation (7-round protocol)
configs := cmp.Keygen(
    curve.Secp256k1{},
    selfID,
    parties,
    threshold,
    pool, // worker pool for parallel processing
)

// 4. Public Key Derivation
publicKey := configs[selfID].PublicKey()
publicKeyHash := crypto.Keccak256Hash(publicKey.Bytes())

// 5. Registration: Record public key hash on-chain
blockchain.RecordPublicKey(groupID, publicKeyHash)

// 6. Confirmation: Group status updated to ACTIVE
blockchain.UpdateGroupStatus(groupID, ACTIVE)
```

**Using FROST Protocol** (For Schnorr/EdDSA):
```go
import "github.com/luxfi/threshold/protocols/frost"

// Optimized for EdDSA chains (Solana, TON, Cardano)
configs := frost.Keygen(
    curve.Ed25519{},
    selfID,
    parties,
    threshold,
    pool,
)
```

#### 3.1.3 Performance Characteristics
Based on LuxFi threshold library benchmarks:

| Operation | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|-----------|--------|--------|---------|----------|
| Key Generation | 12ms | 28ms | 45ms | 82ms |
| Verification | 2ms | 2ms | 2ms | 2ms |

#### 3.1.4 Security Features
- **Identifiable Aborts**: CMP protocol identifies malicious parties
- **Constant-Time Arithmetic**: Uses [saferith](https://github.com/cronokirby/saferith) for timing attack resistance
- **Byzantine Fault Tolerance**: Handles up to t-1 malicious parties
- **Zero-Knowledge Proofs**: For commitment verification
- **Parallel Processing**: Automatic parallelization of heavy computations

### 3.2 Threshold Signature Generation

#### 3.2.1 Signing Protocol

**CMP Signing** (ECDSA):
```go
import "github.com/luxfi/threshold/protocols/cmp"

// 1. Wallet application prepares transaction
txHash := crypto.Keccak256Hash(transaction.Bytes())

// 2. Select m-of-n nodes for signing
signers := selectSigners(threshold, availableNodes)

// 3. Perform threshold signing (4-round protocol)
signature := cmp.Sign(
    config,
    signers,
    txHash[:],
    pool,
)

// 4. Signature is immediately valid on blockchain
// No additional combining step needed
```

**FROST Signing** (Schnorr/EdDSA):
```go
import "github.com/luxfi/threshold/protocols/frost"

// 2-round signing protocol
signature := frost.Sign(
    config,
    signers,
    message,
    pool,
)
```

**With Identifiable Aborts**:
```go
// Detect and identify malicious parties
signature, abortingParty := cmp.SignWithAbortIdentification(
    config,
    signers,
    txHash[:],
    pool,
)

if abortingParty != nil {
    // Report malicious party to blockchain
    blockchain.ReportMaliciousNode(groupID, abortingParty)
}
```

#### 3.2.2 Performance
| Protocol | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|----------|--------|--------|---------|----------|
| CMP Signing | 8ms | 15ms | 24ms | 40ms |
| FROST Signing | 4ms | 8ms | 12ms | 20ms |
| Doerner (2-of-2) | 5ms | N/A | N/A | N/A |

#### 3.2.3 Optimizations
The LuxFi library provides built-in optimizations:

**Pre-signing** (CMP Protocol):
```go
// Generate presigning material in advance (7 rounds)
presigning := cmp.Presign(config, signers, pool)

// Later, sign in just 4 rounds using presigned material
signature := cmp.SignWithPresigning(config, signers, txHash[:], presigning)
```

**Batch Operations**:
```go
// Process multiple signatures efficiently
signatures := make([]*ecdsa.Signature, len(transactions))
for i, tx := range transactions {
    signatures[i] = cmp.Sign(config, signers, tx.Hash(), pool)
}
```

**Parallel Worker Pools**:
```go
// Create worker pool for parallel computation
pool := pool.NewPool(runtime.NumCPU())
defer pool.TearDown()
```

### 3.3 Key Recovery & Dynamic Resharing

The LuxFi library's **LSS (Lux Secure Sharing) protocol** provides sophisticated recovery and resharing capabilities.

#### 3.3.1 Recovery Scenarios
- **Node Failure**: Permanent loss of one or more nodes (below threshold)
- **Wallet Migration**: Moving to new key management group
- **Emergency Access**: User-initiated recovery with authentication
- **Node Addition**: Adding new nodes to existing group without downtime
- **Node Removal**: Removing compromised or unavailable nodes

#### 3.3.2 Standard Recovery Protocol (Share Reconstruction)

**Traditional Recovery** (when threshold is still met):
```go
// 1. Initiation: Wallet owner initiates recovery on-chain
recoveryID := blockchain.InitiateRecovery(groupID, ownerProof)

// 2. Time-lock period (e.g., 7 days)
time.Sleep(timeLockPeriod)

// 3. Share Collection: m-of-n nodes provide shares
shares := collectShares(threshold, activeNodes)

// 4. Key Reconstruction using Lagrange interpolation
reconstructedKey := lagrange.Reconstruct(shares)

// 5. Re-sharing to new group
newConfigs := cmp.Keygen(curve, selfID, newParties, threshold, pool)
```

#### 3.3.3 Dynamic Resharing Protocol (LSS)

**Advanced Recovery with LSS** (zero-downtime, no key reconstruction):
```go
import "github.com/luxfi/threshold/protocols/lss"

// Add new parties without reconstructing the key
newConfigs := lss.Reshare(
    oldConfigs,        // Existing configurations
    newParties,        // New party IDs to add
    newThreshold,      // Updated threshold
    pool,              // Worker pool
)

// Remove parties (e.g., compromised nodes)
reducedConfigs := lss.Reshare(
    configs,
    remainingParties,  // Only the parties to keep
    threshold,
    pool,
)

// Emergency state rollback
manager := lss.NewRollbackManager(maxGenerations)
manager.SaveState(currentGeneration, configs)

// Rollback to previous generation if needed
restoredConfig, err := manager.Rollback(targetGeneration)
```

**Performance**:
| Operation | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|-----------|--------|--------|---------|----------|
| LSS Resharing | 20ms | 35ms | 52ms | 75ms |

#### 3.3.4 Recovery Security

**Multi-Factor Authentication**:
```go
type RecoveryAuthentication struct {
    BlockchainSignature  []byte  // Signature from owner address
    KYCProof            []byte  // Off-chain identity verification
    BiometricHash       []byte  // Biometric verification hash
    SocialRecovery      []byte  // Multi-sig from trusted contacts
    TimeLockProof       uint64  // Proof that time-lock expired
}

// Verify all authentication factors
func VerifyRecoveryAuth(auth RecoveryAuthentication) bool {
    return verifyBlockchainSig(auth.BlockchainSignature) &&
           verifyKYC(auth.KYCProof) &&
           verifyBiometric(auth.BiometricHash) &&
           verifySocialRecovery(auth.SocialRecovery) &&
           verifyTimeLock(auth.TimeLockProof)
}
```

**Time-Lock Enforcement**:
- Minimum 7-day waiting period for recovery initiation
- All group nodes notified of recovery attempt
- Veto mechanism: Any m-of-n nodes can cancel fraudulent recovery
- Automatic alerts sent to wallet owner

**On-Chain Security**:
```solidity
// Smart contract enforcement
function initiateRecovery(uint256 groupId, bytes calldata ownerProof) external {
    require(msg.sender == groups[groupId].walletOwner, "Not owner");
    require(verifyOwnerProof(ownerProof), "Invalid proof");
    
    groups[groupId].recoveryTimestamp = block.timestamp;
    groups[groupId].status = GroupStatus.RECOVERING;
    
    emit RecoveryInitiated(groupId, msg.sender, block.timestamp);
}

function executeRecovery(uint256 groupId) external {
    require(block.timestamp >= groups[groupId].recoveryTimestamp + 7 days, "Time-lock active");
    require(!groups[groupId].vetoActive, "Recovery vetoed");
    // Allow share collection and resharing
}

function vetoRecovery(uint256 groupId, bytes[] calldata nodeSignatures) external {
    require(nodeSignatures.length >= groups[groupId].threshold, "Insufficient signatures");
    groups[groupId].vetoActive = true;
    emit RecoveryVetoed(groupId, block.timestamp);
}
```

#### 3.3.5 Automated Fault Tolerance (LSS)

**Proactive Resharing**:
```go
// Monitor node health
healthChecker := NewHealthChecker(nodes, checkInterval)

healthChecker.OnNodeFailure(func(failedNode party.ID) {
    // Automatic resharing if threshold is at risk
    remainingNodes := removeNode(activeNodes, failedNode)
    
    if len(remainingNodes) <= threshold + 1 {
        // Proactively add new nodes
        newConfigs := lss.Reshare(configs, remainingNodes, threshold, pool)
        
        // Update blockchain
        blockchain.UpdateGroupNodes(groupID, remainingNodes)
    }
})
```

**State Versioning**:
```go
// Track multiple generations of key shares
type KeyGenerationHistory struct {
    Generation  uint64
    Timestamp   time.Time
    Configs     map[party.ID]*cmp.Config
    Parties     []party.ID
    Threshold   int
}

// Maintain history for rollback capability
history := make([]KeyGenerationHistory, 0)
history = append(history, KeyGenerationHistory{
    Generation: 1,
    Timestamp:  time.Now(),
    Configs:    currentConfigs,
    Parties:    currentParties,
    Threshold:  currentThreshold,
})
```

---

## 4. Ethereum-Compatible Chain Support

The system initially targets **Ethereum and EVM-compatible chains** using the LuxFi threshold library's unified adapter system.

### 4.1 Supported EVM Chains

#### 4.1.1 Primary Networks
- **Ethereum Mainnet**: Full EIP support (EIP-155, EIP-1559, EIP-4844)
- **Polygon**: Lower gas costs, faster finality
- **Arbitrum**: Layer 2 scaling, lower fees
- **Optimism**: Layer 2 scaling, OP Stack
- **Base**: Coinbase L2, OP Stack
- **Avalanche C-Chain**: Sub-second finality
- **BNB Smart Chain (BSC)**: High throughput

#### 4.1.2 Additional EVM Networks
Any EVM-compatible chain can be supported with the same implementation:
- zkSync Era, Polygon zkEVM
- Linea, Scroll
- Fantom, Cronos
- Gnosis Chain
- Custom EVM chains

### 4.2 Unified EVM Adapter

```go
import (
    "github.com/luxfi/threshold/protocols/cmp"
    "github.com/luxfi/threshold/protocols/unified/adapters"
    "github.com/luxfi/threshold/pkg/math/curve"
)

// Create Ethereum adapter (works for all EVM chains)
evmAdapter := adapters.NewEthereumAdapter(adapters.SignatureECDSA)

// Generate threshold keys (once, works for all EVM chains)
configs := cmp.Keygen(
    curve.Secp256k1{},
    selfID,
    parties,
    threshold,
    pool,
)

// Derive Ethereum address from public key
publicKey := configs[selfID].PublicKey()
ethereumAddress := evmAdapter.GetAddress(publicKey.Bytes())
```

### 4.3 EVM-Specific Features

#### 4.3.1 Transaction Types

**Legacy Transactions**:
```go
type LegacyTransaction struct {
    Nonce    uint64
    GasPrice *big.Int
    GasLimit uint64
    To       common.Address
    Value    *big.Int
    Data     []byte
}

// Sign legacy transaction
digest, _ := evmAdapter.Digest(legacyTx)
signature := cmp.Sign(config, signers, digest, pool)
```

**EIP-1559 Transactions** (Type 2):
```go
type EIP1559Transaction struct {
    ChainID              *big.Int
    Nonce                uint64
    MaxPriorityFeePerGas *big.Int
    MaxFeePerGas         *big.Int
    GasLimit             uint64
    To                   common.Address
    Value                *big.Int
    Data                 []byte
}

// Sign EIP-1559 transaction
digest, _ := evmAdapter.Digest(eip1559Tx)
signature := cmp.Sign(config, signers, digest, pool)
```

**EIP-4844 Blob Transactions** (Type 3):
```go
type BlobTransaction struct {
    // Standard EIP-1559 fields
    ChainID              *big.Int
    Nonce                uint64
    MaxPriorityFeePerGas *big.Int
    MaxFeePerGas         *big.Int
    GasLimit             uint64
    To                   common.Address
    Value                *big.Int
    Data                 []byte
    
    // Blob-specific fields
    MaxFeePerBlobGas     *big.Int
    BlobVersionedHashes  []common.Hash
}
```

#### 4.3.2 EIP-155 Replay Protection

```go
// Chain ID enforcement for replay protection
type EVMConfig struct {
    ChainID     *big.Int
    ChainName   string
}

var SupportedChains = map[uint64]EVMConfig{
    1:     {big.NewInt(1), "Ethereum Mainnet"},
    137:   {big.NewInt(137), "Polygon"},
    42161: {big.NewInt(42161), "Arbitrum One"},
    10:    {big.NewInt(10), "Optimism"},
    8453:  {big.NewInt(8453), "Base"},
    43114: {big.NewInt(43114), "Avalanche C-Chain"},
    56:    {big.NewInt(56), "BNB Smart Chain"},
}

// Signature includes chain ID via EIP-155
v := signature.V + (chainID * 2) + 35
```

#### 4.3.3 Address Derivation

```go
// Ethereum address from public key
func DeriveEthereumAddress(publicKey *ecdsa.PublicKey) common.Address {
    // Serialize uncompressed public key (65 bytes: 0x04 + x + y)
    pubKeyBytes := crypto.FromECDSAPub(publicKey)
    
    // Hash the public key (excluding 0x04 prefix)
    hash := crypto.Keccak256(pubKeyBytes[1:])
    
    // Take last 20 bytes as address
    address := common.BytesToAddress(hash[12:])
    
    return address
}
```

### 4.4 Smart Contract Wallet Support

#### 4.4.1 EIP-1271 Signature Validation

```solidity
// Threshold wallet contract implementing EIP-1271
contract ThresholdWallet {
    bytes32 public publicKeyHash;
    uint8 public threshold;
    
    // EIP-1271 signature validation
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4) {
        // Verify threshold signature
        if (verifyThresholdSignature(hash, signature)) {
            return 0x1626ba7e; // EIP-1271 magic value
        }
        return 0xffffffff;
    }
    
    function verifyThresholdSignature(
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        // Recover public key from signature
        address recovered = ecrecover(hash, v, r, s);
        
        // Verify against stored public key hash
        return keccak256(abi.encodePacked(recovered)) == publicKeyHash;
    }
}
```

#### 4.4.2 Account Abstraction (EIP-4337)

```solidity
// Threshold signature with account abstraction
contract ThresholdAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // Verify threshold signature on userOpHash
        bytes memory signature = userOp.signature;
        
        if (!verifyThresholdSignature(userOpHash, signature)) {
            return 1; // Invalid signature
        }
        
        return 0; // Valid signature
    }
}
```

### 4.5 Multi-Chain Deployment Architecture

#### 4.5.1 Single Threshold Group, Multiple Chains

```go
// One DKG ceremony generates keys usable across all EVM chains
configs := cmp.Keygen(curve.Secp256k1{}, selfID, parties, threshold, pool)

// Same address on all EVM chains (deterministic)
ethereumAddress := deriveAddress(configs[selfID].PublicKey())

// Sign transactions for different chains
func signForChain(chainID *big.Int, tx Transaction) (*types.Transaction, error) {
    // Set chain-specific parameters
    tx.ChainID = chainID
    
    // Generate digest
    digest := evmAdapter.Digest(tx)
    
    // Sign with threshold (works for any EVM chain)
    signature := cmp.Sign(config, signers, digest, pool)
    
    // Encode with chain-specific v value (EIP-155)
    return evmAdapter.EncodeTransaction(tx, signature, chainID)
}

// Use same wallet across chains
ethTx := signForChain(big.NewInt(1), transaction)      // Ethereum
polyTx := signForChain(big.NewInt(137), transaction)   // Polygon
arbTx := signForChain(big.NewInt(42161), transaction)  // Arbitrum
```

#### 4.5.2 Chain-Specific Configuration

```go
type ChainConfig struct {
    ChainID         *big.Int
    RPCEndpoint     string
    ExplorerURL     string
    NativeCurrency  string
    BlockTime       time.Duration
    Confirmations   uint64
}

var chainConfigs = map[string]ChainConfig{
    "ethereum": {
        ChainID:        big.NewInt(1),
        RPCEndpoint:    "https://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY",
        ExplorerURL:    "https://etherscan.io",
        NativeCurrency: "ETH",
        BlockTime:      12 * time.Second,
        Confirmations:  12,
    },
    "polygon": {
        ChainID:        big.NewInt(137),
        RPCEndpoint:    "https://polygon-rpc.com",
        ExplorerURL:    "https://polygonscan.com",
        NativeCurrency: "MATIC",
        BlockTime:      2 * time.Second,
        Confirmations:  128,
    },
    "arbitrum": {
        ChainID:        big.NewInt(42161),
        RPCEndpoint:    "https://arb1.arbitrum.io/rpc",
        ExplorerURL:    "https://arbiscan.io",
        NativeCurrency: "ETH",
        BlockTime:      250 * time.Millisecond,
        Confirmations:  1,
    },
}
```

### 4.6 Gas Optimization

#### 4.6.1 Signature Encoding

```go
// Compact signature encoding (65 bytes)
func EncodeSignature(sig *ecdsa.Signature, chainID *big.Int) []byte {
    r := sig.R.Bytes()
    s := sig.S.Bytes()
    
    // Calculate v with EIP-155 chain ID
    v := byte(sig.V + (chainID.Uint64() * 2) + 35)
    
    // Encode as 65 bytes: [R(32) || S(32) || V(1)]
    encoded := make([]byte, 65)
    copy(encoded[32-len(r):32], r)
    copy(encoded[64-len(s):64], s)
    encoded[64] = v
    
    return encoded
}
```

#### 4.6.2 Batch Transactions

```go
// Process multiple transactions efficiently
type BatchRequest struct {
    Transactions []*types.Transaction
    ChainID      *big.Int
}

func batchSign(batch BatchRequest, config *cmp.Config, signers []party.ID) ([]*types.Transaction, error) {
    signedTxs := make([]*types.Transaction, len(batch.Transactions))
    
    // Sign all transactions in parallel
    var wg sync.WaitGroup
    for i, tx := range batch.Transactions {
        wg.Add(1)
        go func(idx int, transaction *types.Transaction) {
            defer wg.Done()
            
            digest := evmAdapter.Digest(transaction)
            signature := cmp.Sign(config, signers, digest, pool)
            signedTxs[idx] = evmAdapter.EncodeTransaction(transaction, signature, batch.ChainID)
        }(i, tx)
    }
    
    wg.Wait()
    return signedTxs, nil
}
```

### 4.7 Future Expansion Path

The architecture supports easy addition of non-EVM chains in the future:

**Phase 2 Expansion** (when needed):
- **Bitcoin**: Add Bitcoin adapter (ECDSA/Schnorr)
- **Solana**: Add Solana adapter (EdDSA)
- **Other chains**: Add chain-specific adapters as needed

**Implementation effort**: Minimal changes required due to unified adapter architecture

```go
// Future non-EVM support (example)
// btcAdapter := adapters.NewBitcoinAdapter(adapters.SignatureECDSA)
// solAdapter := adapters.NewSolanaAdapter(adapters.SignatureEdDSA)
```

---

## 5. Communication Protocols

### 4.1 Node-to-Node Communication

#### 4.1.1 Transport Layer
- **Primary**: HTTPS RESTful API
- **Alternative**: Tor hidden services for privacy
- **Message Queue**: For asynchronous operations

#### 4.1.2 API Endpoints (Node Implementation)
```
POST /v1/dkg/participate
  - Initiate DKG ceremony participation

POST /v1/dkg/commitment
  - Submit polynomial commitment

POST /v1/dkg/share
  - Exchange key shares (encrypted)

POST /v1/sign/request
  - Request threshold signature

POST /v1/sign/partial
  - Submit partial signature

POST /v1/recover/share
  - Provide share for recovery operation

GET /v1/health
  - Node health check

GET /v1/status
  - Node operational status
```

#### 4.1.3 Message Format
```json
{
  "version": "1.0",
  "timestamp": 1738368000,
  "groupId": "0x1234...",
  "nodeId": "0xabcd...",
  "messageType": "DKG_COMMITMENT",
  "payload": {
    "commitment": "0x...",
    "proof": "0x..."
  },
  "signature": "0x..."
}
```

### 4.2 Client-to-Node Communication

#### 4.2.1 Client API Endpoints
```
POST /v1/group/create
  - Request group formation

POST /v1/sign/transaction
  - Request transaction signature

POST /v1/recover/initiate
  - Start recovery process

GET /v1/group/{groupId}/status
  - Query group status

GET /v1/group/{groupId}/publickey
  - Retrieve wallet public key
```

### 4.3 Security Considerations

- **Authentication**: All messages signed with node/client private keys
- **Encryption**: End-to-end encryption for sensitive data
- **Rate Limiting**: Prevent DoS attacks
- **Input Validation**: Strict validation of all parameters
- **Replay Protection**: Nonce/timestamp validation

---

## 5. Blockchain Implementation

### 5.1 Smart Contract Architecture

#### 5.1.1 Contract Relationships
```
NodeRegistry (maintains node directory)
    ↓
GroupCoordinator (manages groups)
    ↓
AuditLog (records operations)
```

#### 5.1.2 Access Control
- Node operators: Can register/update their own nodes
- Wallet owners: Can create groups and initiate recovery
- Nodes: Can update group status and record keys
- Public: Read-only access to registry and audit logs

### 5.2 Supported Blockchains

#### 5.2.1 Primary Support
- **Ethereum**: Full smart contract functionality
- **Polygon**: Lower gas costs for high-frequency operations
- **Arbitrum/Optimism**: L2 scaling solutions

#### 5.2.2 Blockchain-Agnostic Design
The protocol should support multiple blockchain backends through adapter pattern:
- Common interface for all blockchain operations
- Chain-specific implementations
- Cross-chain group formation (advanced feature)

### 5.3 Gas Optimization

- Batch operations where possible
- Use events for data storage (audit trail)
- Minimize on-chain storage
- Leverage L2 solutions for frequent operations

---

## 6. Operational Considerations

### 6.1 Node Operator Requirements

#### 6.1.1 Infrastructure
- **Compute**: Sufficient CPU for cryptographic operations
- **Storage**: Secure storage for key shares (HSM recommended)
- **Network**: Reliable internet connectivity, static IP or domain
- **Backup**: Redundant infrastructure and disaster recovery

#### 6.1.2 Security
- **Isolation**: Key management processes in isolated environment
- **Monitoring**: 24/7 security monitoring
- **Updates**: Regular security patches and updates
- **Audits**: Periodic security audits (recommended)

#### 6.1.3 Compliance
- Data protection regulations (GDPR, CCPA)
- Financial regulations (if applicable)
- Export controls for cryptographic software

### 6.2 Client Integration

#### 6.2.1 Wallet Application Flow
1. User creates wallet in application
2. Application queries blockchain for available nodes
3. User selects or app auto-selects nodes (balancing public/permissioned)
4. Application initiates group creation on-chain
5. DKG ceremony completes, wallet receives public key
6. User can now receive funds to this address
7. For spending: app requests threshold signatures from nodes
8. Signed transaction broadcast to cryptocurrency network

#### 6.2.2 User Experience Considerations
- Abstract complexity from end users
- Provide clear status indicators during DKG and signing
- Offer node selection guidance (reputation, geography, etc.)
- Implement retry logic for network failures

### 6.3 Monitoring & Analytics

#### 6.3.1 Metrics to Track
- Node uptime and availability
- DKG ceremony success/failure rates
- Signing request latency
- Recovery operation frequency
- Gas costs per operation
- Network message volume

#### 6.3.2 Alerting
- Node offline notifications
- Failed DKG ceremonies
- Recovery attempts
- Suspicious activity patterns

---

## 7. Security Model

### 7.1 Threat Model

#### 7.1.1 Adversaries
- **Malicious Nodes**: Nodes attempting to steal keys or disrupt operations
- **Network Attackers**: Man-in-the-middle, eavesdropping
- **Compromised Clients**: Malware on wallet applications
- **Blockchain Attacks**: Smart contract vulnerabilities, 51% attacks

#### 7.1.2 Trust Assumptions
- **Honest Threshold**: At least m nodes in group are honest
- **Blockchain Security**: Underlying blockchain is secure
- **Cryptographic Primitives**: ECDSA, hash functions, encryption are secure
- **Node Operators**: Trusted to maintain security best practices

### 7.2 Attack Mitigations

#### 7.2.1 Key Theft Prevention
- Threshold cryptography ensures single node compromise is insufficient
- HSM/secure enclave storage prevents key extraction
- Regular key rotation to new groups (optional future feature)

#### 7.2.2 Denial of Service
- Multiple redundant nodes per group
- Timeout mechanisms for non-responsive nodes
- Rate limiting on smart contracts and APIs
- Economic penalties for node misbehavior (optional)

#### 7.2.3 Privacy Protection
- Minimal on-chain data exposure
- Zero-knowledge proofs where applicable
- Tor support for anonymous communication
- No linkage between wallets and user identities on-chain

---

## 8. Future Enhancements

### 8.1 Short-term Roadmap
- Multi-chain wallet support (Bitcoin, Ethereum, Solana)
- Mobile SDK for wallet developers
- Reference implementation of node software
- Automated node selection algorithms
- Reputation system for nodes

### 8.2 Long-term Vision
- Key rotation without changing wallet addresses
- Proactive secret sharing refresh
- Cross-chain group formation
- Privacy-preserving audit trails (zk-SNARKs)
- Decentralized governance for protocol upgrades
- Integration with hardware wallets
- Support for smart contract wallets (account abstraction)

---

## 9. Implementation Guidelines

### 9.1 Development Phases

#### Phase 1: Core Infrastructure (3-4 months)
- Smart contract development and testing
- Basic node software implementation
- DKG and threshold signature libraries
- Local testnet deployment

#### Phase 2: Security Hardening (2-3 months)
- Security audits
- Penetration testing
- Formal verification of critical components
- HSM integration

#### Phase 3: Public Testnet (2 months)
- Deploy to public testnet (Goerli, Mumbai)
- Developer documentation
- SDK and client library development
- Community testing program

#### Phase 4: Mainnet Launch (1-2 months)
- Gradual rollout with limits
- Monitoring and incident response
- Bug bounty program
- Performance optimization

### 9.2 Technology Stack Recommendations

#### Cryptographic Library
- **Primary**: [LuxFi Threshold Library](https://github.com/luxfi/threshold) v1.0.1+
- **Protocols**: CMP (CGGMP21), FROST, LSS, Doerner
- **Curves**: secp256k1, Ed25519, BIP-340 Schnorr
- **Post-Quantum**: Ringtail lattice-based signatures
- **Features**: Identifiable aborts, constant-time arithmetic, parallel processing

#### Smart Contracts
- **Language**: Solidity 0.8.x
- **Framework**: Hardhat or Foundry
- **Testing**: Extensive unit and integration tests
- **Auditing**: Multiple independent audits

#### Node Software
- **Language**: Go 1.24+ (for LuxFi library compatibility)
- **Framework**: Gin (HTTP server) or gRPC
- **Storage**: PostgreSQL + HSM integration
- **Deployment**: Docker containers, Kubernetes orchestration

#### Client Libraries
- **Go**: Direct LuxFi library integration
- **JavaScript/TypeScript**: Wrapper around Go library (via WASM or RPC)
- **Mobile**: 
  - iOS: Swift wrapper via CGo
  - Android: Kotlin wrapper via gomobile
- **Documentation**: Comprehensive API reference with code examples

#### Infrastructure
- **HSM**: YubiHSM 2, AWS CloudHSM, or Thales Luna
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **Message Queue**: Redis or RabbitMQ for asynchronous operations

---

## 10. Conclusion

This distributed key management system provides a robust, production-ready approach to cryptocurrency wallet security for **Ethereum and all EVM-compatible chains**. By combining the battle-tested LuxFi threshold library with blockchain-based coordination, it eliminates single points of failure while maintaining excellent usability.

### Key Advantages

**Immediate Benefits**:
- **Universal EVM Support**: One implementation works across Ethereum, Polygon, Arbitrum, Optimism, Base, BSC, Avalanche, and any other EVM chain
- **Production-Ready Crypto**: LuxFi library with 100% test coverage, securing billions in assets
- **High Performance**: Sub-25ms transaction signing enables real-time applications
- **Dynamic Resharing**: LSS protocol allows zero-downtime node management
- **Identifiable Aborts**: CMP protocol detects and identifies malicious parties

**Operational Excellence**:
- Same Ethereum address works across all supported chains
- No key reconstruction needed for recovery
- Automated fault tolerance with LSS
- Byzantine fault tolerance up to threshold
- Constant-time cryptographic operations

### Success Factors

The system's success depends on:
1. **Strong cryptographic implementation** - Achieved via LuxFi library
2. **Reliable node operator ecosystem** - Facilitated by blockchain registry
3. **User-friendly client integration** - Simplified by single-address multi-chain support
4. **Ongoing security maintenance** - Supported by established audit processes
5. **Community governance** - Enabled by transparent on-chain coordination

### Deployment Strategy

**Phase 1: EVM Chains** (Current Specification)
- Ethereum mainnet and major L2s
- Production-ready with minimal risk
- Proven library and established ecosystems

**Phase 2: Expansion** (Future)
- Bitcoin support (when needed)
- Additional non-EVM chains (Solana, etc.)
- Minimal architectural changes required
- Adapter pattern supports easy extension

This EVM-first approach provides immediate value while maintaining flexibility for future expansion. The architecture's modularity ensures that adding support for other chains requires only new adapters, not fundamental redesign.

---

## Appendix A: Glossary

- **DKG**: Distributed Key Generation
- **TSS**: Threshold Signature Scheme
- **HSM**: Hardware Security Module
- **m-of-n**: Threshold scheme requiring m signatures from n total participants
- **ECDSA**: Elliptic Curve Digital Signature Algorithm
- **FROST**: Flexible Round-Optimized Schnorr Threshold signatures

## Appendix B: LuxFi Library Integration Guide

### B.1 Installation & Setup

```bash
# Install the library
go get github.com/luxfi/threshold@v1.0.1

# Import required packages
```

```go
import (
    "github.com/luxfi/threshold/protocols/cmp"
    "github.com/luxfi/threshold/protocols/frost"
    "github.com/luxfi/threshold/protocols/lss"
    "github.com/luxfi/threshold/protocols/unified/adapters"
    "github.com/luxfi/threshold/pkg/math/curve"
    "github.com/luxfi/threshold/pkg/party"
    "github.com/luxfi/threshold/pkg/pool"
)
```

### B.2 Protocol Selection Guide

| Use Case | Recommended Protocol | Reason |
|----------|---------------------|---------|
| Bitcoin/Ethereum ECDSA | CMP | Identifiable aborts, production proven |
| Solana/TON/Cardano EdDSA | FROST | Fastest signing, 2-round protocol |
| Dynamic node management | LSS | Zero-downtime resharing |
| Two-party wallets | Doerner | Optimized for 2-of-2, lowest latency |
| Post-quantum security | Ringtail | Future-proof against quantum attacks |

### B.3 Security Best Practices

1. **Worker Pool Management**
```go
// Create pool with CPU cores, ensure cleanup
pool := pool.NewPool(runtime.NumCPU())
defer pool.TearDown()
```

2. **Secure Communication**
```go
// Always use TLS 1.3+ for node communication
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    Certificates: []tls.Certificate{cert},
}
```

3. **Share Storage**
```go
// Never store shares in plaintext
encryptedShare := aes.GCMEncrypt(shareBytes, masterKey)
hsm.Store("share_" + groupID, encryptedShare)
```

## Appendix C: References

- Canetti et al. (2021): "UC Non-Interactive, Proactive, Threshold ECDSA" - [CGGMP21](https://eprint.iacr.org/2021/060)
- Komlo & Goldberg (2020): "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" - [FROST](https://eprint.iacr.org/2020/852.pdf)
- Doerner et al. (2018): "Threshold ECDSA from ECDSA Assumptions" - [Doerner](https://eprint.iacr.org/2018/499.pdf)
- LuxFi Threshold Library: [GitHub](https://github.com/luxfi/threshold)
- Bitcoin Protocol: [Bitcoin Developer Guide](https://developer.bitcoin.org/devguide/)
- Ethereum: [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- XRPL: [XRP Ledger Documentation](https://xrpl.org/)

## Appendix D: Example Scenarios

### Scenario 1: Personal Multi-Chain EVM Wallet
Alice wants to secure her cryptocurrency across multiple EVM chains:
1. Alice's wallet app queries 20 available public nodes on Ethereum mainnet
2. App selects 7 nodes based on geography and reputation
3. Group created with 4-of-7 threshold using smart contract on Ethereum
4. DKG ceremony completes in 30 seconds using CMP protocol
5. Alice receives her Ethereum address (same address works on all EVM chains)
6. She can now transact on Ethereum, Polygon, Arbitrum, Base, etc.
7. Any 4 nodes can sign transactions for any supported EVM chain

### Scenario 2: DeFi Protocol Treasury
DeFi protocol XYZ needs high-security custody across multiple chains:
1. Selects 5 permissioned nodes operated by trusted security firms
2. Adds 5 public nodes for redundancy (10 total)
3. Sets 7-of-10 threshold for high security
4. Deploys smart contract wallet on Ethereum with EIP-1271 support
5. Same threshold wallet address deployed on Polygon, Arbitrum, Optimism
6. All transactions require coordination of 7+ parties
7. Can move assets between chains while maintaining same security model

### Scenario 3: Cross-Chain Asset Management
Trading firm manages assets across 5 EVM chains:
1. Uses single threshold group (5-of-9) for all chains
2. Same Ethereum address holds assets on:
   - Ethereum (ETH, USDC, WBTC)
   - Polygon (MATIC, USDC)
   - Arbitrum (ETH, ARB, GMX)
   - Optimism (ETH, OP)
   - Base (ETH, USDC)
3. Pre-generates signing material for low-latency trading
4. Can sign and broadcast transactions in under 20ms
5. Monitors node health and uses LSS to replace failing nodes

### Scenario 4: Key Recovery After Node Failures
Bob's wallet group loses 3 nodes due to infrastructure failure:
1. Original setup: 5-of-9 threshold, 3 nodes permanently offline
2. Bob initiates recovery from new device with owner signature
3. 7-day time-lock begins, all remaining nodes are notified
4. Bob completes KYC verification with recovery service
5. After time-lock, remaining 6 nodes use LSS to reshare
6. New nodes recruited to restore 5-of-9 configuration
7. Bob regains full access without reconstructing master key
8. Same Ethereum address maintained across all chains

### Scenario 5: Enterprise Payroll System
Company processes payroll on Polygon for low fees:
1. Finance team uses threshold wallet (3-of-5 approval)
2. Payroll system prepares batch of 1000 employee payments
3. Threshold signature generated for batch transaction
4. Transaction broadcast to Polygon with sub-$0.01 fees
5. All transactions confirmed within 30 seconds
6. Same wallet can move funds from Ethereum to Polygon as needed
7. Audit trail maintained on-chain via smart contract events
