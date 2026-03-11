;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; message.lisp - Cross-chain message passing protocol
;;;; Message creation, signing, verification, and finality tracking

(in-package #:cl-bridges.message)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defconstant +message-version+ 1
  "Current message protocol version.")

(defconstant +default-finality-depth+ 12
  "Default number of confirmations required for message finality.")

(defparameter *message-nonces* (make-hash-table :test 'equal)
  "Per-chain nonce tracking. Key = chain-id, Value = next nonce.")

(defparameter *processed-nonces* (make-hash-table :test 'equal)
  "Per-chain last processed nonce. Key = (source-chain . dest-chain).")

;;; ============================================================================
;;; Error Conditions
;;; ============================================================================

(define-condition messaging-error (error)
  ((message :initarg :message :reader messaging-error-message))
  (:report (lambda (c s)
             (format s "Messaging error: ~A" (messaging-error-message c)))))

(define-condition message-not-found-error (messaging-error)
  ((message-id :initarg :message-id :reader error-message-id))
  (:report (lambda (c s)
             (format s "Message not found: ~A" (error-message-id c)))))

(define-condition invalid-message-error (messaging-error)
  ((reason :initarg :reason :reader invalid-message-reason))
  (:report (lambda (c s)
             (format s "Invalid message: ~A" (invalid-message-reason c)))))

(define-condition finality-not-reached-error (messaging-error)
  ((confirmations :initarg :confirmations :reader finality-confirmations)
   (required :initarg :required :reader finality-required))
  (:report (lambda (c s)
             (format s "Finality not reached: ~A/~A confirmations"
                     (finality-confirmations c) (finality-required c)))))

(define-condition delivery-failed-error (messaging-error)
  ((attempts :initarg :attempts :reader delivery-attempts)
   (last-error :initarg :last-error :reader delivery-last-error :initform nil))
  (:report (lambda (c s)
             (format s "Delivery failed after ~A attempts~@[: ~A~]"
                     (delivery-attempts c) (delivery-last-error c)))))

(define-condition sequence-error (messaging-error)
  ((expected :initarg :expected :reader sequence-expected)
   (received :initarg :received :reader sequence-received))
  (:report (lambda (c s)
             (format s "Sequence error: expected ~A, received ~A"
                     (sequence-expected c) (sequence-received c)))))

(define-condition timeout-error (messaging-error)
  ((timeout :initarg :timeout :reader timeout-duration))
  (:report (lambda (c s)
             (format s "Message timed out after ~A seconds" (timeout-duration c)))))

;;; ============================================================================
;;; Cross-Chain Message Structure
;;; ============================================================================

(defstruct cross-chain-message
  "A cross-chain message."
  (id nil :type (or null (simple-array (unsigned-byte 8) 32)))
  (source-chain nil :type (or null keyword string))
  (dest-chain nil :type (or null keyword string))
  (sender nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (receiver nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (payload nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (nonce 0 :type (unsigned-byte 64))
  (timestamp 0 :type (unsigned-byte 64))
  (signature nil :type (or null (simple-array (unsigned-byte 8) (*)))))

;; Accessor aliases for cleaner API
(defun message-id (msg)
  (cross-chain-message-id msg))

(defun message-source-chain (msg)
  (cross-chain-message-source-chain msg))

(defun message-dest-chain (msg)
  (cross-chain-message-dest-chain msg))

(defun message-sender (msg)
  (cross-chain-message-sender msg))

(defun message-receiver (msg)
  (cross-chain-message-receiver msg))

(defun message-payload (msg)
  (cross-chain-message-payload msg))

(defun message-nonce (msg)
  (cross-chain-message-nonce msg))

(defun message-timestamp (msg)
  (cross-chain-message-timestamp msg))

(defun message-signature (msg)
  (cross-chain-message-signature msg))

;;; ============================================================================
;;; Message Proof Structure
;;; ============================================================================

(defstruct message-proof
  "Proof of message inclusion in a block."
  (message-id nil :type (or null (simple-array (unsigned-byte 8) 32)))
  (block-hash nil :type (or null (simple-array (unsigned-byte 8) 32)))
  (block-height 0 :type (unsigned-byte 64))
  (tx-index 0 :type fixnum)
  (merkle-path nil :type list))

;; Accessor aliases
(defun proof-message-id (proof)
  (message-proof-message-id proof))

(defun proof-block-hash (proof)
  (message-proof-block-hash proof))

(defun proof-block-height (proof)
  (message-proof-block-height proof))

(defun proof-tx-index (proof)
  (message-proof-tx-index proof))

(defun proof-merkle-path (proof)
  (message-proof-merkle-path proof))

;;; ============================================================================
;;; Message Status Structure
;;; ============================================================================

(defstruct message-status
  "Status tracking for a cross-chain message."
  (message-id nil :type (or null (simple-array (unsigned-byte 8) 32)))
  (state :pending :type keyword)  ; :pending :confirming :delivered :failed
  (confirmations 0 :type fixnum)
  (retries 0 :type fixnum)
  (last-attempt 0 :type (unsigned-byte 64)))

;; Accessor aliases
(defun status-message-id (status)
  (message-status-message-id status))

(defun status-state (status)
  (message-status-state status))

(defun status-confirmations (status)
  (message-status-confirmations status))

(defun status-retries (status)
  (message-status-retries status))

(defun status-last-attempt (status)
  (message-status-last-attempt status))

;;; ============================================================================
;;; Message Creation
;;; ============================================================================

(defun create-message (source-chain dest-chain sender receiver payload)
  "Create a new cross-chain message."
  (let* ((nonce (get-next-nonce source-chain))
         (timestamp (unix-timestamp))
         (msg (make-cross-chain-message
               :source-chain source-chain
               :dest-chain dest-chain
               :sender (etypecase sender
                         (string (hex-to-bytes sender))
                         (vector sender))
               :receiver (etypecase receiver
                           (string (hex-to-bytes receiver))
                           (vector receiver))
               :payload (etypecase payload
                          (string (map 'vector #'char-code payload))
                          (vector payload))
               :nonce nonce
               :timestamp timestamp))
         (msg-hash (hash-message msg)))
    (setf (cross-chain-message-id msg) msg-hash)
    msg))

(defun hash-message (msg)
  "Compute message hash (ID) from message fields."
  (let ((data (serialize-message msg)))
    (sha256 data)))

(defun serialize-message (msg)
  "Serialize message to bytes for hashing/transmission."
  (let* ((source (etypecase (message-source-chain msg)
                   (keyword (symbol-name (message-source-chain msg)))
                   (string (message-source-chain msg))))
         (dest (etypecase (message-dest-chain msg)
                 (keyword (symbol-name (message-dest-chain msg)))
                 (string (message-dest-chain msg))))
         (source-bytes (map 'vector #'char-code source))
         (dest-bytes (map 'vector #'char-code dest)))
    (concat-bytes
     (vector +message-version+)
     (serialize-varint (length source-bytes))
     source-bytes
     (serialize-varint (length dest-bytes))
     dest-bytes
     (serialize-varint (length (message-sender msg)))
     (message-sender msg)
     (serialize-varint (length (message-receiver msg)))
     (message-receiver msg)
     (serialize-uint64-le (message-nonce msg))
     (serialize-uint64-le (message-timestamp msg))
     (serialize-varint (length (message-payload msg)))
     (message-payload msg))))

(defun deserialize-message (bytes)
  "Deserialize message from bytes."
  (let ((offset 0))
    (flet ((get-byte ()
             (prog1 (aref bytes offset)
               (incf offset)))
           (read-bytes (n)
             (prog1 (subseq-bytes bytes offset (+ offset n))
               (incf offset n)))
           (read-varint ()
             (multiple-value-bind (val consumed)
                 (deserialize-varint bytes offset)
               (incf offset consumed)
               val)))
      (let* ((version (get-byte))
             (source-len (read-varint))
             (source (map 'string #'code-char (read-bytes source-len)))
             (dest-len (read-varint))
             (dest (map 'string #'code-char (read-bytes dest-len)))
             (sender-len (read-varint))
             (sender (read-bytes sender-len))
             (receiver-len (read-varint))
             (receiver (read-bytes receiver-len))
             (nonce (deserialize-uint64-le bytes offset))
             (_ (incf offset 8))
             (timestamp (deserialize-uint64-le bytes offset))
             (_ (incf offset 8))
             (payload-len (read-varint))
             (payload (read-bytes payload-len)))
        (declare (ignore _ version))
        (make-cross-chain-message
         :source-chain source
         :dest-chain dest
         :sender sender
         :receiver receiver
         :payload payload
         :nonce nonce
         :timestamp timestamp)))))

;;; ============================================================================
;;; Message Verification
;;; ============================================================================

(defun verify-message (msg)
  "Verify message structure and required fields. Returns T or signals error."
  (unless (message-source-chain msg)
    (error 'invalid-message-error :reason "Missing source chain"))
  (unless (message-dest-chain msg)
    (error 'invalid-message-error :reason "Missing destination chain"))
  (unless (message-sender msg)
    (error 'invalid-message-error :reason "Missing sender"))
  (unless (message-receiver msg)
    (error 'invalid-message-error :reason "Missing receiver"))
  (unless (message-payload msg)
    (error 'invalid-message-error :reason "Missing payload"))
  (when (zerop (message-timestamp msg))
    (error 'invalid-message-error :reason "Invalid timestamp"))
  t)

(defun verify-message-proof (proof merkle-root)
  "Verify message proof against a Merkle root."
  (let ((current (message-proof-message-id proof)))
    (loop for (sibling . direction) in (message-proof-merkle-path proof)
          do (setf current
                   (ecase direction
                     (:left (sha256 (concat-bytes sibling current)))
                     (:right (sha256 (concat-bytes current sibling))))))
    (bytes-equal-p current merkle-root)))

(defun verify-message-signature (msg public-key)
  "Verify message signature (stub - implement with actual crypto)."
  (declare (ignore public-key))
  ;; Signature verification would go here
  ;; For now, just check signature exists
  (and (message-signature msg)
       (> (length (message-signature msg)) 0)))

;;; ============================================================================
;;; Finality Tracking
;;; ============================================================================

(defun check-message-finality (status &optional (required +default-finality-depth+))
  "Check if message has reached finality."
  (>= (message-status-confirmations status) required))

(defun get-confirmation-count (status)
  "Get current confirmation count for message."
  (message-status-confirmations status))

(defun is-message-final-p (status &optional (required +default-finality-depth+))
  "Predicate: has message reached finality?"
  (check-message-finality status required))

;;; ============================================================================
;;; Sequence Management
;;; ============================================================================

(defun get-next-nonce (chain-id)
  "Get and increment nonce for a chain."
  (let ((current (gethash chain-id *message-nonces* 0)))
    (setf (gethash chain-id *message-nonces*) (1+ current))
    current))

(defun verify-nonce (source-chain dest-chain nonce)
  "Verify that nonce is the expected next nonce."
  (let* ((key (cons source-chain dest-chain))
         (expected (1+ (gethash key *processed-nonces* -1))))
    (if (= nonce expected)
        t
        (error 'sequence-error :expected expected :received nonce))))

(defun get-last-processed-nonce (source-chain dest-chain)
  "Get last processed nonce for a channel."
  (gethash (cons source-chain dest-chain) *processed-nonces* -1))

;;; ============================================================================
;;; End of message.lisp
;;; ============================================================================
