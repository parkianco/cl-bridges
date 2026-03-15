;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

;;;; test-bridges.lisp - Test suite for cl-bridges
;;;; Basic functionality tests

(in-package #:cl-bridges.test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)
(defvar *test-results* nil)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn
           ,@body
           (incf *pass-count*)
           (push (cons ',name :pass) *test-results*)
           (format t "  PASS: ~A~%" ',name)
           t)
       (error (e)
         (incf *fail-count*)
         (push (cons ',name (princ-to-string e)) *test-results*)
         (format t "  FAIL: ~A - ~A~%" ',name e)
         nil))))

(defun assert-equal (expected actual &optional message)
  "Assert that two values are equal."
  (unless (equal expected actual)
    (error "~A~%  Expected: ~S~%  Actual: ~S"
           (or message "Assertion failed")
           expected actual)))

(defun assert-true (value &optional message)
  "Assert that value is true."
  (unless value
    (error "~A~%  Expected: true~%  Actual: ~S"
           (or message "Assertion failed")
           value)))

(defun assert-bytes-equal (expected actual &optional message)
  "Assert that two byte vectors are equal."
  (unless (and (= (length expected) (length actual))
               (every #'= expected actual))
    (error "~A~%  Expected: ~A~%  Actual: ~A"
           (or message "Byte vectors not equal")
           (cl-bridges:bytes-to-hex expected)
           (cl-bridges:bytes-to-hex actual))))

;;; ============================================================================
;;; SHA-256 Tests
;;; ============================================================================

(deftest test-sha256-empty
  "Test SHA-256 of empty input."
  (let* ((input (make-array 0 :element-type '(unsigned-byte 8)))
         (hash (cl-bridges:sha256 input))
         (expected "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    (assert-equal expected (cl-bridges:bytes-to-hex hash))))

(deftest test-sha256-hello
  "Test SHA-256 of 'hello'."
  (let* ((input (map 'vector #'char-code "hello"))
         (hash (cl-bridges:sha256 input))
         (expected "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"))
    (assert-equal expected (cl-bridges:bytes-to-hex hash))))

(deftest test-double-sha256
  "Test double SHA-256."
  (let* ((input (map 'vector #'char-code "test"))
         (hash (cl-bridges:double-sha256 input)))
    (assert-equal 32 (length hash))))

;;; ============================================================================
;;; Hex Encoding Tests
;;; ============================================================================

(deftest test-bytes-to-hex
  "Test byte vector to hex string conversion."
  (let ((bytes #(0 1 15 16 255)))
    (assert-equal "00010f10ff" (cl-bridges:bytes-to-hex bytes))))

(deftest test-hex-to-bytes
  "Test hex string to byte vector conversion."
  (let ((hex "00010f10ff")
        (expected #(0 1 15 16 255)))
    (assert-bytes-equal expected (cl-bridges:hex-to-bytes hex))))

(deftest test-hex-roundtrip
  "Test hex encoding roundtrip."
  (let ((original #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
    (assert-bytes-equal original
                        (cl-bridges:hex-to-bytes
                         (cl-bridges:bytes-to-hex original)))))

;;; ============================================================================
;;; Merkle Proof Tests
;;; ============================================================================

(deftest test-compute-merkle-root-single
  "Test Merkle root of single leaf."
  (let* ((leaf (cl-bridges:sha256 (map 'vector #'char-code "test")))
         (root (cl-bridges:compute-merkle-root (list leaf))))
    (assert-bytes-equal leaf root)))

(deftest test-compute-merkle-root-multiple
  "Test Merkle root of multiple leaves."
  (let* ((leaves (list (cl-bridges:sha256 (map 'vector #'char-code "a"))
                       (cl-bridges:sha256 (map 'vector #'char-code "b"))
                       (cl-bridges:sha256 (map 'vector #'char-code "c"))
                       (cl-bridges:sha256 (map 'vector #'char-code "d"))))
         (root (cl-bridges:compute-merkle-root leaves)))
    (assert-equal 32 (length root))))

(deftest test-build-merkle-tree
  "Test Merkle tree construction."
  (let* ((leaves (list (cl-bridges:sha256 (map 'vector #'char-code "a"))
                       (cl-bridges:sha256 (map 'vector #'char-code "b"))))
         (tree (cl-bridges:build-merkle-tree leaves)))
    (assert-equal 2 (length tree))  ; Two levels
    (assert-equal 2 (length (first tree)))  ; Two leaves
    (assert-equal 1 (length (second tree)))))  ; One root

(deftest test-merkle-proof-verification
  "Test Merkle proof creation and verification."
  (let* ((leaves (list (cl-bridges:sha256 (map 'vector #'char-code "a"))
                       (cl-bridges:sha256 (map 'vector #'char-code "b"))
                       (cl-bridges:sha256 (map 'vector #'char-code "c"))
                       (cl-bridges:sha256 (map 'vector #'char-code "d"))))
         (root (cl-bridges:compute-merkle-root leaves))
         (path (cl-bridges:build-merkle-path leaves 0))
         (proof (cl-bridges:make-merkle-proof
                 :leaf (first leaves)
                 :root root
                 :path path
                 :index 0)))
    (assert-true (cl-bridges:verify-merkle-proof proof))))

;;; ============================================================================
;;; Message Tests
;;; ============================================================================

(deftest test-create-message
  "Test message creation."
  (let ((msg (cl-bridges.message:create-message
              :chain-a :chain-b
              (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1)
              (make-array 20 :element-type '(unsigned-byte 8) :initial-element 2)
              (map 'vector #'char-code "test payload"))))
    (assert-true (cl-bridges:cross-chain-message-p msg))
    (assert-true (cl-bridges:message-id msg))
    (assert-equal :chain-a (cl-bridges:message-source-chain msg))
    (assert-equal :chain-b (cl-bridges:message-dest-chain msg))))

(deftest test-message-serialization
  "Test message serialization and deserialization."
  (let* ((msg (cl-bridges.message:create-message
               :source :dest
               (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1)
               (make-array 20 :element-type '(unsigned-byte 8) :initial-element 2)
               (map 'vector #'char-code "hello")))
         (serialized (cl-bridges:serialize-message msg))
         (deserialized (cl-bridges:deserialize-message serialized)))
    (assert-equal (cl-bridges:message-nonce msg)
                  (cl-bridges:message-nonce deserialized))))

(deftest test-verify-message
  "Test message verification."
  (let ((msg (cl-bridges.message:create-message
              :chain-a :chain-b
              (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1)
              (make-array 20 :element-type '(unsigned-byte 8) :initial-element 2)
              (map 'vector #'char-code "test"))))
    (assert-true (cl-bridges:verify-message msg))))

;;; ============================================================================
;;; Bridge Tests
;;; ============================================================================

(deftest test-initialize-bridge
  "Test bridge initialization."
  (let ((bridge (cl-bridges:initialize-bridge :chain-a :chain-b)))
    (assert-true (cl-bridges:bridge-p bridge))
    (assert-equal :chain-a (cl-bridges:bridge-source-chain bridge))
    (assert-equal :chain-b (cl-bridges:bridge-dest-chain bridge))
    (assert-equal :initialized (cl-bridges:bridge-status bridge))))

(deftest test-bridge-lifecycle
  "Test bridge start/stop."
  (let ((bridge (cl-bridges:initialize-bridge :test-src :test-dst)))
    (assert-equal :initialized (cl-bridges:bridge-status bridge))
    (cl-bridges:start-bridge bridge)
    (assert-equal :running (cl-bridges:bridge-status bridge))
    (cl-bridges:stop-bridge bridge)
    (assert-equal :stopped (cl-bridges:bridge-status bridge))))

(deftest test-get-bridge-status
  "Test bridge status retrieval."
  (let* ((bridge (cl-bridges:initialize-bridge :src :dst :id "test-bridge"))
         (status (cl-bridges:get-bridge-status bridge)))
    (assert-equal "test-bridge" (getf status :id))
    (assert-equal :initialized (getf status :status))))

;;; ============================================================================
;;; Relayer Tests
;;; ============================================================================

(deftest test-create-relayer
  "Test relayer creation."
  (let ((relayer (cl-bridges:make-relayer :id "test-relayer"
                                          :chains '(:a :b))))
    (assert-true (cl-bridges:relayer-p relayer))
    (assert-equal 0 (cl-bridges:relayer-pending-count relayer))))

(deftest test-queue-message
  "Test message queueing."
  (let* ((relayer (cl-bridges:make-relayer :id "test" :chains '(:a :b)))
         (msg (cl-bridges.message:create-message
               :a :b
               (make-array 20 :element-type '(unsigned-byte 8))
               (make-array 20 :element-type '(unsigned-byte 8))
               (map 'vector #'char-code "test"))))
    (cl-bridges:queue-message relayer msg)
    (assert-equal 1 (cl-bridges:relayer-pending-count relayer))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0
        *test-results* nil)
  (format t "~%Running cl-bridges tests...~%~%")

  ;; SHA-256 tests
  (format t "SHA-256 Tests:~%")
  (test-sha256-empty)
  (test-sha256-hello)
  (test-double-sha256)

  ;; Hex encoding tests
  (format t "~%Hex Encoding Tests:~%")
  (test-bytes-to-hex)
  (test-hex-to-bytes)
  (test-hex-roundtrip)

  ;; Merkle proof tests
  (format t "~%Merkle Proof Tests:~%")
  (test-compute-merkle-root-single)
  (test-compute-merkle-root-multiple)
  (test-build-merkle-tree)
  (test-merkle-proof-verification)

  ;; Message tests
  (format t "~%Message Tests:~%")
  (test-create-message)
  (test-message-serialization)
  (test-verify-message)

  ;; Bridge tests
  (format t "~%Bridge Tests:~%")
  (test-initialize-bridge)
  (test-bridge-lifecycle)
  (test-get-bridge-status)

  ;; Relayer tests
  (format t "~%Relayer Tests:~%")
  (test-create-relayer)
  (test-queue-message)

  ;; Summary
  (format t "~%========================================~%")
  (format t "Test Results: ~A passed, ~A failed, ~A total~%"
          *pass-count* *fail-count* *test-count*)
  (format t "========================================~%~%")

  (values (zerop *fail-count*) *pass-count* *fail-count*))

;;; ============================================================================
;;; End of test-bridges.lisp
;;; ============================================================================
