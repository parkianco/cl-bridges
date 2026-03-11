;;;; relayer.lisp - Relayer protocol for cross-chain message delivery
;;;; Handles message queuing, retry logic, and delivery confirmation

(in-package #:cl-bridges.relayer)

;;; ============================================================================
;;; Configuration
;;; ============================================================================

(defparameter *max-retries* 5
  "Maximum retry attempts for message delivery.")

(defparameter *retry-delay-base* 1
  "Base delay in seconds for exponential backoff.")

(defparameter *retry-delay-max* 300
  "Maximum delay in seconds between retries.")

(defparameter *batch-size* 100
  "Maximum messages to process in a batch.")

;;; ============================================================================
;;; Error Conditions
;;; ============================================================================

(define-condition relayer-error (error)
  ((message :initarg :message :reader relayer-error-message))
  (:report (lambda (c s)
             (format s "Relayer error: ~A" (relayer-error-message c)))))

(define-condition delivery-failed-error (relayer-error)
  ((attempts :initarg :attempts :reader delivery-attempts)
   (last-error :initarg :last-error :reader delivery-last-error))
  (:report (lambda (c s)
             (format s "Delivery failed after ~A attempts: ~A"
                     (delivery-attempts c) (delivery-last-error c)))))

(define-condition retry-exhausted-error (relayer-error)
  ((message-id :initarg :message-id :reader retry-message-id))
  (:report (lambda (c s)
             (format s "Retry exhausted for message: ~A" (retry-message-id c)))))

(define-condition chain-unavailable-error (relayer-error)
  ((chain-id :initarg :chain-id :reader unavailable-chain-id))
  (:report (lambda (c s)
             (format s "Chain unavailable: ~A" (unavailable-chain-id c)))))

;;; ============================================================================
;;; Relayer Structure
;;; ============================================================================

(defstruct relayer
  "A cross-chain message relayer."
  (id nil :type (or null string))
  (chains nil :type list)              ; List of supported chain IDs
  (pending-queue nil :type list)       ; Messages awaiting delivery
  (retry-queue nil :type list)         ; Messages awaiting retry
  (delivered nil :type list)           ; Successfully delivered messages
  (failed nil :type list)              ; Failed messages
  (pending-count 0 :type fixnum)
  (delivered-count 0 :type fixnum)
  (failed-count 0 :type fixnum)
  (running-p nil :type boolean)
  (delivery-handlers (make-hash-table :test 'equal) :type hash-table))

;; Accessor aliases
(defun relayer-id (r) (relayer-id r))
(defun relayer-chains (r) (relayer-chains r))
(defun relayer-pending-count (r) (relayer-pending-count r))
(defun relayer-delivered-count (r) (relayer-delivered-count r))
(defun relayer-failed-count (r) (relayer-failed-count r))

;;; ============================================================================
;;; Queued Message Structure
;;; ============================================================================

(defstruct queued-message
  "A message in the relay queue."
  (message nil :type (or null cross-chain-message))
  (proof nil :type (or null message-proof))
  (queued-at 0 :type (unsigned-byte 64))
  (retry-count 0 :type fixnum)
  (next-retry 0 :type (unsigned-byte 64))
  (last-error nil :type (or null string)))

;;; ============================================================================
;;; Relayer Lifecycle
;;; ============================================================================

(defun start-relayer (relayer)
  "Start the relayer."
  (setf (relayer-running-p relayer) t)
  relayer)

(defun stop-relayer (relayer)
  "Stop the relayer."
  (setf (relayer-running-p relayer) nil)
  relayer)

;;; ============================================================================
;;; Message Queueing
;;; ============================================================================

(defun queue-message (relayer message &optional proof)
  "Add a message to the relay queue."
  (let ((queued (make-queued-message
                 :message message
                 :proof proof
                 :queued-at (unix-timestamp))))
    (push queued (relayer-pending-queue relayer))
    (incf (relayer-pending-count relayer))
    queued))

(defun relay-message (relayer message &optional proof)
  "Queue and attempt to relay a message."
  (let ((queued (queue-message relayer message proof)))
    (when (relayer-running-p relayer)
      (attempt-delivery relayer queued))
    queued))

(defun process-queue (relayer)
  "Process pending messages in the queue."
  (let ((now (unix-timestamp))
        (processed 0)
        (to-process (min *batch-size* (length (relayer-pending-queue relayer)))))
    ;; Process pending queue
    (loop for queued in (subseq (relayer-pending-queue relayer) 0 to-process)
          when (relayer-running-p relayer)
          do (attempt-delivery relayer queued)
             (incf processed))
    ;; Process retry queue
    (loop for queued in (relayer-retry-queue relayer)
          when (and (relayer-running-p relayer)
                    (<= (queued-message-next-retry queued) now))
          do (attempt-delivery relayer queued)
             (incf processed))
    processed))

(defun get-queue-status (relayer)
  "Get current queue status."
  (list :pending (relayer-pending-count relayer)
        :delivered (relayer-delivered-count relayer)
        :failed (relayer-failed-count relayer)
        :retry-queue (length (relayer-retry-queue relayer))))

;;; ============================================================================
;;; Message Delivery
;;; ============================================================================

(defun attempt-delivery (relayer queued)
  "Attempt to deliver a queued message."
  (let* ((message (queued-message-message queued))
         (dest-chain (message-dest-chain message))
         (handler (gethash dest-chain (relayer-delivery-handlers relayer))))
    (handler-case
        (if handler
            (progn
              (funcall handler message (queued-message-proof queued))
              (mark-delivered relayer queued))
            (error 'chain-unavailable-error :chain-id dest-chain))
      (error (e)
        (handle-delivery-failure relayer queued (princ-to-string e))))))

(defun deliver-message (relayer message proof)
  "Directly deliver a message (bypassing queue)."
  (let ((dest-chain (message-dest-chain message))
        (handler (gethash dest-chain (relayer-delivery-handlers relayer))))
    (if handler
        (funcall handler message proof)
        (error 'chain-unavailable-error :chain-id dest-chain))))

(defun mark-delivered (relayer queued)
  "Mark a message as successfully delivered."
  (setf (relayer-pending-queue relayer)
        (remove queued (relayer-pending-queue relayer)))
  (setf (relayer-retry-queue relayer)
        (remove queued (relayer-retry-queue relayer)))
  (push queued (relayer-delivered relayer))
  (decf (relayer-pending-count relayer))
  (incf (relayer-delivered-count relayer))
  t)

(defun handle-delivery-failure (relayer queued error-msg)
  "Handle a delivery failure."
  (setf (queued-message-last-error queued) error-msg)
  (incf (queued-message-retry-count queued))
  (if (max-retries-exceeded-p queued)
      (mark-failed relayer queued)
      (schedule-retry relayer queued)))

(defun mark-failed (relayer queued)
  "Mark a message as permanently failed."
  (setf (relayer-pending-queue relayer)
        (remove queued (relayer-pending-queue relayer)))
  (setf (relayer-retry-queue relayer)
        (remove queued (relayer-retry-queue relayer)))
  (push queued (relayer-failed relayer))
  (decf (relayer-pending-count relayer))
  (incf (relayer-failed-count relayer))
  nil)

;;; ============================================================================
;;; Delivery Confirmation
;;; ============================================================================

(defun confirm-delivery (relayer message-id)
  "Confirm that a message was delivered."
  (let ((queued (find message-id (relayer-pending-queue relayer)
                      :key (lambda (q)
                             (message-id (queued-message-message q)))
                      :test #'bytes-equal-p)))
    (when queued
      (mark-delivered relayer queued))))

(defun get-delivery-status (relayer message-id)
  "Get delivery status for a message."
  (cond ((find message-id (relayer-delivered relayer)
               :key (lambda (q) (message-id (queued-message-message q)))
               :test #'bytes-equal-p)
         :delivered)
        ((find message-id (relayer-failed relayer)
               :key (lambda (q) (message-id (queued-message-message q)))
               :test #'bytes-equal-p)
         :failed)
        ((find message-id (relayer-retry-queue relayer)
               :key (lambda (q) (message-id (queued-message-message q)))
               :test #'bytes-equal-p)
         :retrying)
        ((find message-id (relayer-pending-queue relayer)
               :key (lambda (q) (message-id (queued-message-message q)))
               :test #'bytes-equal-p)
         :pending)
        (t :unknown)))

(defun acknowledge-message (relayer message-id)
  "Acknowledge receipt of a message."
  (confirm-delivery relayer message-id))

;;; ============================================================================
;;; Retry Logic
;;; ============================================================================

(defun schedule-retry (relayer queued)
  "Schedule a message for retry with exponential backoff."
  (let* ((retry-count (queued-message-retry-count queued))
         (delay (min *retry-delay-max*
                     (* *retry-delay-base* (expt 2 retry-count))))
         (next-retry (+ (unix-timestamp) delay)))
    (setf (queued-message-next-retry queued) next-retry)
    ;; Move from pending to retry queue
    (setf (relayer-pending-queue relayer)
          (remove queued (relayer-pending-queue relayer)))
    (push queued (relayer-retry-queue relayer))
    next-retry))

(defun retry-message (relayer message-id)
  "Manually retry a failed message."
  (let ((queued (or (find message-id (relayer-failed relayer)
                         :key (lambda (q) (message-id (queued-message-message q)))
                         :test #'bytes-equal-p)
                   (find message-id (relayer-retry-queue relayer)
                         :key (lambda (q) (message-id (queued-message-message q)))
                         :test #'bytes-equal-p))))
    (when queued
      (setf (queued-message-retry-count queued) 0)
      (setf (queued-message-next-retry queued) 0)
      ;; Move to pending queue
      (setf (relayer-failed relayer)
            (remove queued (relayer-failed relayer)))
      (setf (relayer-retry-queue relayer)
            (remove queued (relayer-retry-queue relayer)))
      (push queued (relayer-pending-queue relayer))
      (when (relayer-running-p relayer)
        (attempt-delivery relayer queued))
      t)))

(defun get-retry-count (queued)
  "Get retry count for a queued message."
  (queued-message-retry-count queued))

(defun max-retries-exceeded-p (queued)
  "Check if max retries have been exceeded."
  (>= (queued-message-retry-count queued) *max-retries*))

(defun reset-retry-count (queued)
  "Reset retry count for a queued message."
  (setf (queued-message-retry-count queued) 0))

;;; ============================================================================
;;; Fee Estimation
;;; ============================================================================

(defun estimate-relay-fee (relayer dest-chain message-size)
  "Estimate relay fee for a message."
  (declare (ignore relayer))
  ;; Base fee + per-byte cost
  ;; This is a stub - actual implementation would query chain-specific costs
  (let ((base-fee 1000)
        (per-byte 10))
    (+ base-fee (* per-byte message-size))))

(defun get-gas-price (relayer chain-id)
  "Get current gas price for a chain."
  (declare (ignore relayer chain-id))
  ;; Stub - would query actual gas price
  20000000000) ; 20 gwei default

(defun calculate-delivery-cost (relayer message)
  "Calculate total delivery cost for a message."
  (let* ((dest-chain (message-dest-chain message))
         (message-bytes (serialize-message message))
         (gas-price (get-gas-price relayer dest-chain))
         (relay-fee (estimate-relay-fee relayer dest-chain (length message-bytes))))
    (+ relay-fee (* gas-price 21000)))) ; Base gas for relay tx

;;; ============================================================================
;;; End of relayer.lisp
;;; ============================================================================
