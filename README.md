# cl-bridges

Cross-chain bridge protocols for Common Lisp.

## Features

- **Cross-chain message passing** with finality tracking
- **Merkle proof verification** for bridge operations
- **Relayer protocol** for message delivery with retry logic
- **Light client verification** patterns
- **Zero dependencies** - pure Common Lisp implementation

## Installation

```lisp
(asdf:load-system :cl-bridges)
```

## Quick Start

```lisp
;; Create a bridge between two chains
(defvar *bridge* (cl-bridges:initialize-bridge :chain-a :chain-b))

;; Start the bridge
(cl-bridges:start-bridge *bridge*)

;; Send a message
(cl-bridges:send-message *bridge* "Hello from Chain A"
                         :sender #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)
                         :receiver #(20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1))

;; Check status
(cl-bridges:get-bridge-status *bridge*)

;; Stop when done
(cl-bridges:stop-bridge *bridge*)
```

## Packages

- `cl-bridges` - Main interface, re-exports common functionality
- `cl-bridges.message` - Cross-chain message creation and verification
- `cl-bridges.proof` - Merkle proof verification
- `cl-bridges.relayer` - Message relay and delivery
- `cl-bridges.util` - Crypto primitives (SHA-256), serialization

## API Reference

### Bridge Operations

```lisp
;; Create and manage bridges
(initialize-bridge source-chain dest-chain &key id finality-depth)
(start-bridge bridge)
(stop-bridge bridge)
(get-bridge-status bridge)

;; Send and receive messages
(send-message bridge payload &key sender receiver)
(receive-message bridge message proof)
(get-pending-messages bridge)
(get-message-status bridge message-id)

;; Verification
(verify-proof bridge proof merkle-root)
(verify-inclusion bridge proof merkle-root)
(verify-finality bridge message-id)
```

### Message Operations

```lisp
;; Create messages
(create-message source-chain dest-chain sender receiver payload)
(hash-message msg)
(serialize-message msg)
(deserialize-message bytes)

;; Verify messages
(verify-message msg)
(verify-message-proof proof merkle-root)
(check-message-finality status &optional required-depth)
(is-message-final-p status &optional required-depth)
```

### Merkle Proofs

```lisp
;; Build proofs
(compute-merkle-root leaves)
(build-merkle-tree leaves)
(build-merkle-path leaves index)

;; Verify proofs
(verify-merkle-proof proof)
(verify-state-proof proof)
(verify-inclusion-proof proof merkle-root)
```

### Crypto Utilities

```lisp
;; Hashing
(sha256 bytes)         ; Returns 32-byte hash
(sha256-hex bytes)     ; Returns hex string
(double-sha256 bytes)  ; SHA256(SHA256(bytes))

;; Hex encoding
(bytes-to-hex bytes)
(hex-to-bytes hex-string)
```

## Testing

```lisp
(asdf:test-system :cl-bridges)
```

Or manually:

```lisp
(asdf:load-system :cl-bridges/test)
(cl-bridges.test:run-tests)
```

## License

Dual-licensed under MIT or Apache-2.0. See LICENSE for details.

## Acknowledgments

Extracted from the CLPIC project. Implements patterns from IBC, Ethereum light clients, and standard Merkle proof verification.
