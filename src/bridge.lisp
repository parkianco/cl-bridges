;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; bridge.lisp - Main bridge interface
;;;; Unified API for cross-chain bridge operations

(in-package #:cl-bridges)

;;; ============================================================================
;;; Version and Constants
;;; ============================================================================

;; Use defvar to avoid SBCL DEFCONSTANT-UNEQL on string reload
(defvar +version+ "1.0.0"
  "cl-bridges version.")

(defparameter *default-finality-depth* 12
  "Default number of confirmations for finality.")

(defparameter *message-timeout* 3600
  "Default message timeout in seconds (1 hour).")

(defparameter *max-message-size* 65536
  "Maximum message payload size in bytes (64KB).")

;;; ============================================================================
;;; Bridge Structure
;;; ============================================================================

(defstruct bridge
  "A cross-chain bridge instance."
  (id nil :type (or null string))
  (source-chain nil :type (or null keyword string))
  (dest-chain nil :type (or null keyword string))
  (status :initialized :type keyword)  ; :initialized :running :stopped :error
  (relayer nil :type (or null cl-bridges.relayer:relayer))
  (finality-depth *default-finality-depth* :type fixnum)
  (pending-messages (make-hash-table :test 'equal) :type hash-table)
  (message-statuses (make-hash-table :test 'equal) :type hash-table)
  (proof-verifier nil :type (or null function))
  (created-at 0 :type (unsigned-byte 64))
  (started-at 0 :type (unsigned-byte 64)))

;;; ============================================================================
;;; Bridge Lifecycle
;;; ============================================================================

(defun initialize-bridge (source-chain dest-chain &key id finality-depth)
  "Create and initialize a new bridge."
  (let ((bridge (make-bridge
                 :id (or id (format nil "bridge-~A-~A" source-chain dest-chain))
                 :source-chain source-chain
                 :dest-chain dest-chain
                 :finality-depth (or finality-depth *default-finality-depth*)
                 :relayer (cl-bridges.relayer:make-relayer
                           :id (format nil "relayer-~A-~A" source-chain dest-chain)
                           :chains (list source-chain dest-chain))
                 :created-at (cl-bridges.util:unix-timestamp))))
    (setf (bridge-status bridge) :initialized)
    bridge))

(defun start-bridge (bridge)
  "Start the bridge."
  (cl-bridges.relayer:start-relayer (bridge-relayer bridge))
  (setf (bridge-status bridge) :running
        (bridge-started-at bridge) (cl-bridges.util:unix-timestamp))
  bridge)

(defun stop-bridge (bridge)
  "Stop the bridge."
  (cl-bridges.relayer:stop-relayer (bridge-relayer bridge))
  (setf (bridge-status bridge) :stopped)
  bridge)

(defun get-bridge-status (bridge)
  "Get detailed bridge status."
  (list :id (bridge-id bridge)
        :status (bridge-status bridge)
        :source-chain (bridge-source-chain bridge)
        :dest-chain (bridge-dest-chain bridge)
        :finality-depth (bridge-finality-depth bridge)
        :pending-count (hash-table-count (bridge-pending-messages bridge))
        :relayer-status (cl-bridges.relayer:get-queue-status (bridge-relayer bridge))
        :created-at (bridge-created-at bridge)
        :started-at (bridge-started-at bridge)))

;;; ============================================================================
;;; Message Operations
;;; ============================================================================

(defun send-message (bridge payload &key sender receiver)
  "Send a message through the bridge."
  (unless (eq (bridge-status bridge) :running)
    (error "Bridge not running"))
  (let* ((sender-bytes (or sender
                           (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (receiver-bytes (or receiver
                             (make-array 20 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
         (payload-bytes (etypecase payload
                          (string (map 'vector #'char-code payload))
                          (vector payload)))
         (message (cl-bridges.message:create-message
                   (bridge-source-chain bridge)
                   (bridge-dest-chain bridge)
                   sender-bytes
                   receiver-bytes
                   payload-bytes)))
    ;; Validate
    (when (> (length payload-bytes) *max-message-size*)
      (error "Message payload exceeds maximum size"))
    (cl-bridges.message:verify-message message)
    ;; Track and relay
    (let ((msg-id (cl-bridges.message:message-id message)))
      (setf (gethash msg-id (bridge-pending-messages bridge)) message)
      (setf (gethash msg-id (bridge-message-statuses bridge))
            (cl-bridges.message:make-message-status
             :message-id msg-id
             :state :pending))
      (cl-bridges.relayer:relay-message (bridge-relayer bridge) message)
      message)))

(defun receive-message (bridge message proof)
  "Process an incoming message."
  ;; Verify the message
  (cl-bridges.message:verify-message message)
  ;; Verify the proof if verifier is configured
  (when (bridge-proof-verifier bridge)
    (funcall (bridge-proof-verifier bridge) proof))
  ;; Track the message
  (let ((msg-id (cl-bridges.message:message-id message)))
    (setf (gethash msg-id (bridge-pending-messages bridge)) message)
    (setf (gethash msg-id (bridge-message-statuses bridge))
          (cl-bridges.message:make-message-status
           :message-id msg-id
           :state :received)))
  message)

(defun get-pending-messages (bridge)
  "Get all pending messages."
  (loop for msg being the hash-values of (bridge-pending-messages bridge)
        collect msg))

(defun get-message-status (bridge message-id)
  "Get status of a specific message."
  (let ((status (gethash message-id (bridge-message-statuses bridge))))
    (if status
        (list :state (cl-bridges.message:status-state status)
              :confirmations (cl-bridges.message:status-confirmations status)
              :retries (cl-bridges.message:status-retries status))
        :unknown)))

;;; ============================================================================
;;; Verification
;;; ============================================================================

(defun verify-proof (bridge proof merkle-root)
  "Verify a proof using the bridge's configured verifier."
  (if (bridge-proof-verifier bridge)
      (funcall (bridge-proof-verifier bridge) proof merkle-root)
      (cl-bridges.message:verify-message-proof proof merkle-root)))

(defun verify-inclusion (bridge proof merkle-root)
  "Verify inclusion proof."
  (cl-bridges.proof:verify-merkle-proof
   (cl-bridges.proof:make-merkle-proof
    :leaf (cl-bridges.message:proof-message-id proof)
    :root merkle-root
    :path (cl-bridges.message:proof-merkle-path proof))))

(defun verify-finality (bridge message-id)
  "Check if a message has reached finality."
  (let ((status (gethash message-id (bridge-message-statuses bridge))))
    (when status
      (cl-bridges.message:is-message-final-p status (bridge-finality-depth bridge)))))

;;; ============================================================================
;;; End of bridge.lisp
;;; ============================================================================
