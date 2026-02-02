# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Research project for OneKey threshold signing using the `luxfi/threshold` library. The project explores threshold key generation and transaction signing with chain adapters (e.g., Ethereum).

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run a specific test
go test -run TestBasic

# Run tests with verbose output
go test -v ./...
```

## Key Dependencies

- `github.com/luxfi/threshold` - Threshold cryptography library providing:
  - `pkg/math/curve` - Elliptic curve implementations (Secp256k1)
  - `pkg/party` - Party ID management for MPC protocols
  - `pkg/pool` - Worker pool for parallel computation
  - `protocols/cmp` - CMP protocol for key generation and signing
  - `protocols/unified/adapters` - Chain-specific adapters for transaction signing
