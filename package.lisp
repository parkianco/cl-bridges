;;;; package.lisp - Package definitions for cl-bridges
;;;; Cross-chain bridge protocols

(in-package #:cl-user)

;;; ============================================================================
;;; Utility Package (Internal)
;;; ============================================================================

(defpackage #:cl-bridges.util
  (:use #:cl)
  (:documentation "Internal utilities for cl-bridges: crypto primitives, serialization.")
  (:export
   ;; Hashing (SHA256 - inlined pure CL implementation)
   #:sha256
   #:sha256-hex
   #:double-sha256

   ;; Hex encoding
   #:bytes-to-hex
   #:hex-to-bytes

   ;; Serialization
   #:serialize-uint32-le
   #:serialize-uint64-le
   #:deserialize-uint32-le
   #:deserialize-uint64-le
   #:serialize-varint
   #:deserialize-varint

   ;; Byte vector utilities
   #:concat-bytes
   #:subseq-bytes
   #:bytes-equal-p

   ;; Time utilities
   #:unix-timestamp
   #:timestamp-to-universal
   #:universal-to-timestamp))

;;; ============================================================================
;;; Proof Package
;;; ============================================================================

(defpackage #:cl-bridges.proof
  (:use #:cl #:cl-bridges.util)
  (:documentation "Merkle proof verification for cross-chain bridges.
Provides inclusion proofs, state proofs, and proof aggregation.")
  (:export
   ;; Merkle proof structure
   #:merkle-proof
   #:make-merkle-proof
   #:merkle-proof-p
   #:merkle-proof-leaf
   #:merkle-proof-root
   #:merkle-proof-path
   #:merkle-proof-index

   ;; Proof verification
   #:verify-merkle-proof
   #:compute-merkle-root
   #:build-merkle-tree
   #:build-merkle-path

   ;; State proofs
   #:state-proof
   #:make-state-proof
   #:state-proof-p
   #:state-proof-key
   #:state-proof-value
   #:state-proof-root
   #:state-proof-siblings
   #:verify-state-proof

   ;; Inclusion proofs
   #:inclusion-proof
   #:make-inclusion-proof
   #:inclusion-proof-p
   #:inclusion-proof-item-hash
   #:inclusion-proof-block-hash
   #:inclusion-proof-block-height
   #:inclusion-proof-merkle-path
   #:verify-inclusion-proof

   ;; Proof aggregation
   #:aggregate-proofs
   #:verify-aggregated-proof

   ;; Error conditions
   #:proof-error
   #:invalid-proof-error
   #:proof-verification-failed))

;;; ============================================================================
;;; Message Package
;;; ============================================================================

(defpackage #:cl-bridges.message
  (:use #:cl #:cl-bridges.util #:cl-bridges.proof)
  (:documentation "Cross-chain message passing protocol.
Provides message creation, signing, verification, and finality tracking.")
  (:export
   ;; Error conditions
   #:messaging-error
   #:message-not-found-error
   #:invalid-message-error
   #:finality-not-reached-error
   #:delivery-failed-error
   #:sequence-error
   #:timeout-error

   ;; Cross-chain message
   #:cross-chain-message
   #:make-cross-chain-message
   #:cross-chain-message-p
   #:message-id
   #:message-source-chain
   #:message-dest-chain
   #:message-sender
   #:message-receiver
   #:message-payload
   #:message-nonce
   #:message-timestamp
   #:message-signature

   ;; Message proof
   #:message-proof
   #:make-message-proof
   #:message-proof-p
   #:proof-message-id
   #:proof-block-hash
   #:proof-block-height
   #:proof-tx-index
   #:proof-merkle-path

   ;; Message status
   #:message-status
   #:make-message-status
   #:message-status-p
   #:status-message-id
   #:status-state
   #:status-confirmations
   #:status-retries
   #:status-last-attempt

   ;; Message creation
   #:create-message
   #:hash-message
   #:serialize-message
   #:deserialize-message

   ;; Message verification
   #:verify-message
   #:verify-message-proof
   #:verify-message-signature

   ;; Finality tracking
   #:check-message-finality
   #:get-confirmation-count
   #:is-message-final-p

   ;; Sequence management
   #:get-next-nonce
   #:verify-nonce
   #:get-last-processed-nonce

   ;; Constants
   #:+default-finality-depth+
   #:+message-version+))

;;; ============================================================================
;;; Relayer Package
;;; ============================================================================

(defpackage #:cl-bridges.relayer
  (:use #:cl #:cl-bridges.util #:cl-bridges.proof #:cl-bridges.message)
  (:documentation "Relayer protocol for cross-chain message delivery.
Handles message queuing, retry logic, and delivery confirmation.")
  (:export
   ;; Relayer
   #:relayer
   #:make-relayer
   #:relayer-p
   #:relayer-id
   #:relayer-chains
   #:relayer-pending-count
   #:relayer-delivered-count
   #:relayer-failed-count

   ;; Relayer operations
   #:start-relayer
   #:stop-relayer
   #:relay-message
   #:queue-message
   #:process-queue
   #:get-queue-status

   ;; Delivery
   #:deliver-message
   #:confirm-delivery
   #:get-delivery-status
   #:acknowledge-message

   ;; Retry logic
   #:retry-message
   #:schedule-retry
   #:get-retry-count
   #:max-retries-exceeded-p
   #:reset-retry-count

   ;; Fee estimation
   #:estimate-relay-fee
   #:get-gas-price
   #:calculate-delivery-cost

   ;; Configuration
   #:*max-retries*
   #:*retry-delay-base*
   #:*retry-delay-max*
   #:*batch-size*

   ;; Error conditions
   #:relayer-error
   #:delivery-failed-error
   #:retry-exhausted-error
   #:chain-unavailable-error))

;;; ============================================================================
;;; Bridge Package (Main Interface)
;;; ============================================================================

(defpackage #:cl-bridges
  (:use #:cl)
  (:documentation "Cross-chain bridge protocols for Common Lisp.

This package provides the main interface for cross-chain bridge operations:
- Message passing between chains
- Merkle proof verification
- Relayer protocol
- Light client verification patterns

Usage:
  (cl-bridges:make-bridge :source :chain-a :dest :chain-b)
  (cl-bridges:send-message bridge payload)
  (cl-bridges:verify-message-proof bridge proof)")

  ;; Re-export from util
  (:import-from #:cl-bridges.util
                #:sha256 #:sha256-hex #:double-sha256
                #:bytes-to-hex #:hex-to-bytes)
  (:export #:sha256 #:sha256-hex #:double-sha256
           #:bytes-to-hex #:hex-to-bytes)

  ;; Re-export from proof
  (:import-from #:cl-bridges.proof
                #:merkle-proof #:make-merkle-proof #:merkle-proof-p
                #:verify-merkle-proof #:compute-merkle-root
                #:build-merkle-tree #:build-merkle-path
                #:state-proof #:make-state-proof #:verify-state-proof
                #:inclusion-proof #:make-inclusion-proof #:verify-inclusion-proof)
  (:export #:merkle-proof #:make-merkle-proof #:merkle-proof-p
           #:verify-merkle-proof #:compute-merkle-root
           #:build-merkle-tree #:build-merkle-path
           #:state-proof #:make-state-proof #:verify-state-proof
           #:inclusion-proof #:make-inclusion-proof #:verify-inclusion-proof)

  ;; Re-export from message
  (:import-from #:cl-bridges.message
                #:cross-chain-message #:make-cross-chain-message #:cross-chain-message-p
                #:message-id #:message-source-chain #:message-dest-chain
                #:message-sender #:message-receiver #:message-payload
                #:create-message #:hash-message #:serialize-message #:deserialize-message
                #:verify-message #:verify-message-proof
                #:check-message-finality #:is-message-final-p)
  (:export #:cross-chain-message #:make-cross-chain-message #:cross-chain-message-p
           #:message-id #:message-source-chain #:message-dest-chain
           #:message-sender #:message-receiver #:message-payload
           #:create-message #:hash-message #:serialize-message #:deserialize-message
           #:verify-message #:verify-message-proof
           #:check-message-finality #:is-message-final-p)

  ;; Re-export from relayer
  (:import-from #:cl-bridges.relayer
                #:relayer #:make-relayer #:relayer-p
                #:start-relayer #:stop-relayer
                #:relay-message #:queue-message
                #:deliver-message #:confirm-delivery
                #:estimate-relay-fee)
  (:export #:relayer #:make-relayer #:relayer-p
           #:start-relayer #:stop-relayer
           #:relay-message #:queue-message
           #:deliver-message #:confirm-delivery
           #:estimate-relay-fee)

  ;; Bridge interface
  (:export
   ;; Bridge type
   #:bridge
   #:make-bridge
   #:bridge-p
   #:bridge-id
   #:bridge-source-chain
   #:bridge-dest-chain
   #:bridge-status
   #:bridge-relayer

   ;; Bridge lifecycle
   #:initialize-bridge
   #:start-bridge
   #:stop-bridge
   #:get-bridge-status

   ;; Message operations
   #:send-message
   #:receive-message
   #:get-pending-messages
   #:get-message-status

   ;; Verification
   #:verify-proof
   #:verify-inclusion
   #:verify-finality

   ;; Configuration
   #:*default-finality-depth*
   #:*message-timeout*
   #:*max-message-size*

   ;; Version
   #:+version+))

;;; ============================================================================
;;; Test Package
;;; ============================================================================

(defpackage #:cl-bridges.test
  (:use #:cl #:cl-bridges)
  (:documentation "Test suite for cl-bridges")
  (:export #:run-tests))

;;; ============================================================================
;;; End of Package Definitions
;;; ============================================================================
