;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-bridges.asd - Cross-Chain Bridge Protocols for Common Lisp
;;;; Standalone extraction from Parkian

(asdf:defsystem #:"cl-bridges"
  :name "cl-bridges"
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "MIT OR Apache-2.0"
  :description "Cross-chain bridge protocols: message passing, proof verification, relaying"
  :long-description "Standalone cross-chain bridge library providing:
- Cross-chain message passing with finality tracking
- Merkle proof verification for bridge operations
- Relayer protocol for message delivery
- Light client verification patterns
- Atomic swap HTLCs"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "proof")
                             (:file "message")
                             (:file "relayer")
                             (:file "bridge"))))
  :in-order-to ((asdf:test-op (test-op "cl-bridges/test"))))

(asdf:defsystem #:"cl-bridges/test"
  :name "cl-bridges-test"
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "MIT OR Apache-2.0"
  :description "Tests for cl-bridges"
  :depends-on ("cl-bridges")
  :serial t
  :components ((:module "test"
                :serial t
                :components ((:file "test-bridges"))))
  :perform (asdf:test-op (op c)
             (let ((result (uiop:symbol-call :cl-bridges.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
