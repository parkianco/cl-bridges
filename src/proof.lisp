;;;; proof.lisp - Merkle proof verification for cross-chain bridges
;;;; Provides inclusion proofs, state proofs, and proof aggregation

(in-package #:cl-bridges.proof)

;;; ============================================================================
;;; Error Conditions
;;; ============================================================================

(define-condition proof-error (error)
  ((message :initarg :message :reader proof-error-message))
  (:report (lambda (condition stream)
             (format stream "Proof error: ~A" (proof-error-message condition)))))

(define-condition invalid-proof-error (proof-error)
  ((reason :initarg :reason :reader invalid-proof-reason))
  (:report (lambda (condition stream)
             (format stream "Invalid proof: ~A" (invalid-proof-reason condition)))))

(define-condition proof-verification-failed (proof-error)
  ((expected :initarg :expected :reader proof-expected)
   (actual :initarg :actual :reader proof-actual))
  (:report (lambda (condition stream)
             (format stream "Proof verification failed: expected ~A, got ~A"
                     (proof-expected condition) (proof-actual condition)))))

;;; ============================================================================
;;; Merkle Proof Structure
;;; ============================================================================

(defstruct merkle-proof
  "A Merkle inclusion proof."
  (leaf nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (root nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (path nil :type list)   ; List of (hash . direction) pairs
  (index 0 :type fixnum)) ; Leaf index in tree

;;; ============================================================================
;;; Merkle Tree Operations
;;; ============================================================================

(defun hash-pair (left right)
  "Hash two 32-byte values together. Returns 32-byte hash."
  (sha256 (concat-bytes left right)))

(defun compute-merkle-root (leaves)
  "Compute Merkle root from list of leaf hashes."
  (when (null leaves)
    (return-from compute-merkle-root
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
  (when (= (length leaves) 1)
    (return-from compute-merkle-root (first leaves)))
  ;; Pad to power of 2 by duplicating last element
  (let* ((n (length leaves))
         (next-pow2 (expt 2 (ceiling (log n 2))))
         (padded (append leaves
                         (make-list (- next-pow2 n)
                                    :initial-element (car (last leaves))))))
    (loop while (> (length padded) 1)
          do (setf padded
                   (loop for (left right) on padded by #'cddr
                         collect (hash-pair left right))))
    (first padded)))

(defun build-merkle-tree (leaves)
  "Build complete Merkle tree from leaves. Returns list of levels (bottom to top)."
  (when (null leaves)
    (return-from build-merkle-tree nil))
  (let* ((n (length leaves))
         (next-pow2 (expt 2 (ceiling (log (max n 1) 2))))
         (padded (append leaves
                         (make-list (- next-pow2 n)
                                    :initial-element (car (last leaves)))))
         (levels (list (coerce padded 'vector))))
    (loop while (> (length (car levels)) 1)
          for current = (car levels)
          for next-level = (make-array (/ (length current) 2))
          do (loop for i from 0 below (length next-level)
                   do (setf (aref next-level i)
                            (hash-pair (aref current (* 2 i))
                                       (aref current (+ (* 2 i) 1)))))
             (push next-level levels))
    (nreverse levels)))

(defun build-merkle-path (leaves index)
  "Build Merkle proof path for leaf at INDEX."
  (let* ((tree (build-merkle-tree leaves))
         (path '())
         (idx index))
    (loop for level in (butlast tree)
          for sibling-idx = (if (evenp idx) (1+ idx) (1- idx))
          for direction = (if (evenp idx) :right :left)
          do (when (< sibling-idx (length level))
               (push (cons (aref level sibling-idx) direction) path))
             (setf idx (floor idx 2)))
    (nreverse path)))

;;; ============================================================================
;;; Merkle Proof Verification
;;; ============================================================================

(defun verify-merkle-proof (proof)
  "Verify a Merkle proof. Returns T if valid, signals error otherwise."
  (declare (type merkle-proof proof))
  (let ((current (merkle-proof-leaf proof))
        (path (merkle-proof-path proof)))
    (unless current
      (error 'invalid-proof-error :reason "Missing leaf hash"))
    (loop for (sibling . direction) in path
          do (setf current
                   (ecase direction
                     (:left (hash-pair sibling current))
                     (:right (hash-pair current sibling)))))
    (if (bytes-equal-p current (merkle-proof-root proof))
        t
        (error 'proof-verification-failed
               :expected (bytes-to-hex (merkle-proof-root proof))
               :actual (bytes-to-hex current)))))

;;; ============================================================================
;;; State Proof Structure
;;; ============================================================================

(defstruct state-proof
  "A state proof for key-value inclusion in state trie."
  (key nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (value nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (root nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (siblings nil :type list)) ; List of sibling hashes

(defun verify-state-proof (proof)
  "Verify a state proof. Returns T if valid."
  (declare (type state-proof proof))
  (let* ((key (state-proof-key proof))
         (value (state-proof-value proof))
         (leaf-hash (sha256 (concat-bytes key value)))
         (current leaf-hash)
         (siblings (state-proof-siblings proof)))
    (loop for (sibling . direction) in siblings
          do (setf current
                   (ecase direction
                     (:left (hash-pair sibling current))
                     (:right (hash-pair current sibling)))))
    (if (bytes-equal-p current (state-proof-root proof))
        t
        (error 'proof-verification-failed
               :expected (bytes-to-hex (state-proof-root proof))
               :actual (bytes-to-hex current)))))

;;; ============================================================================
;;; Inclusion Proof Structure
;;; ============================================================================

(defstruct inclusion-proof
  "Proof that an item is included in a block."
  (item-hash nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (block-hash nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (block-height 0 :type (unsigned-byte 64))
  (merkle-path nil :type list))

(defun verify-inclusion-proof (proof merkle-root)
  "Verify an inclusion proof against a known Merkle root."
  (declare (type inclusion-proof proof))
  (let ((current (inclusion-proof-item-hash proof)))
    (unless current
      (error 'invalid-proof-error :reason "Missing item hash"))
    (loop for (sibling . direction) in (inclusion-proof-merkle-path proof)
          do (setf current
                   (ecase direction
                     (:left (hash-pair sibling current))
                     (:right (hash-pair current sibling)))))
    (if (bytes-equal-p current merkle-root)
        t
        (error 'proof-verification-failed
               :expected (bytes-to-hex merkle-root)
               :actual (bytes-to-hex current)))))

;;; ============================================================================
;;; Proof Aggregation
;;; ============================================================================

(defstruct aggregated-proof
  "Multiple proofs aggregated together."
  (proofs nil :type list)
  (aggregate-root nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defun aggregate-proofs (proofs)
  "Aggregate multiple proofs into a single proof structure."
  (let* ((roots (mapcar (lambda (p)
                          (etypecase p
                            (merkle-proof (merkle-proof-root p))
                            (state-proof (state-proof-root p))
                            (inclusion-proof (inclusion-proof-block-hash p))))
                        proofs))
         (aggregate-root (compute-merkle-root roots)))
    (make-aggregated-proof :proofs proofs :aggregate-root aggregate-root)))

(defun verify-aggregated-proof (aggregated-proof)
  "Verify all proofs in an aggregated proof."
  (declare (type aggregated-proof aggregated-proof))
  (loop for proof in (aggregated-proof-proofs aggregated-proof)
        always (handler-case
                   (etypecase proof
                     (merkle-proof (verify-merkle-proof proof))
                     (state-proof (verify-state-proof proof)))
                 (proof-error () nil))))

;;; ============================================================================
;;; End of proof.lisp
;;; ============================================================================
