;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; util.lisp - Internal utilities for cl-bridges
;;;; Crypto primitives and serialization helpers

(in-package #:cl-bridges.util)

;;; ============================================================================
;;; SHA-256 Implementation (Pure Common Lisp)
;;; ============================================================================
;;; Based on FIPS 180-4. No external dependencies.

(defvar *sha256-k*
  (make-array 64 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
                #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3
                #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
                #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
                #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
                #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
                #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
                #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208
                #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))
  "SHA-256 round constants.")

(declaim (inline rotr32 shr32))

(defun rotr32 (x n)
  "32-bit right rotation."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logior (ash x (- n)) (logand #xffffffff (ash x (- 32 n)))))

(defun shr32 (x n)
  "32-bit right shift."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (ash x (- n)))

(declaim (inline ch32 maj32 sigma0-256 sigma1-256 gamma0-256 gamma1-256))

(defun ch32 (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand (lognot x) z)))

(defun maj32 (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sigma0-256 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (rotr32 x 2) (rotr32 x 13) (rotr32 x 22)))

(defun sigma1-256 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (rotr32 x 6) (rotr32 x 11) (rotr32 x 25)))

(defun gamma0-256 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (rotr32 x 7) (rotr32 x 18) (shr32 x 3)))

(defun gamma1-256 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (rotr32 x 17) (rotr32 x 19) (shr32 x 10)))

(defun sha256-pad (message)
  "Pad message according to SHA-256 spec."
  (declare (type (simple-array (unsigned-byte 8) (*)) message)
           (optimize (speed 3) (safety 1)))
  (let* ((len (length message))
         (bit-len (* len 8))
         ;; Pad to 64 bytes - 8 (for length) + 1 (for 0x80)
         (pad-len (- 64 (mod (+ len 9) 64)))
         (total-len (+ len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type fixnum len bit-len pad-len total-len))
    ;; Copy message
    (replace padded message)
    ;; Append 0x80
    (setf (aref padded len) #x80)
    ;; Append length as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (logand #xff (ash bit-len (* -8 i)))))
    padded))

(defun sha256-process-block (block h)
  "Process a single 512-bit block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) h)
           (optimize (speed 3) (safety 0)))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0))
        (a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
    (declare (type (simple-array (unsigned-byte 32) (64)) w)
             (type (unsigned-byte 32) a b c d e f g hh))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          do (setf (aref w i)
                   (logior (ash (aref block (* i 4)) 24)
                           (ash (aref block (+ (* i 4) 1)) 16)
                           (ash (aref block (+ (* i 4) 2)) 8)
                           (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xffffffff
                           (+ (gamma1-256 (aref w (- i 2)))
                              (aref w (- i 7))
                              (gamma0-256 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Main loop
    (loop for i from 0 below 64
          for t1 = (logand #xffffffff
                           (+ hh (sigma1-256 e) (ch32 e f g)
                              (aref +sha256-k+ i) (aref w i)))
          for t2 = (logand #xffffffff (+ (sigma0-256 a) (maj32 a b c)))
          do (psetf hh g
                    g f
                    f e
                    e (logand #xffffffff (+ d t1))
                    d c
                    c b
                    b a
                    a (logand #xffffffff (+ t1 t2))))
    ;; Add back to hash
    (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
          (aref h 1) (logand #xffffffff (+ (aref h 1) b))
          (aref h 2) (logand #xffffffff (+ (aref h 2) c))
          (aref h 3) (logand #xffffffff (+ (aref h 3) d))
          (aref h 4) (logand #xffffffff (+ (aref h 4) e))
          (aref h 5) (logand #xffffffff (+ (aref h 5) f))
          (aref h 6) (logand #xffffffff (+ (aref h 6) g))
          (aref h 7) (logand #xffffffff (+ (aref h 7) hh)))
    h))

(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE (byte vector). Returns 32-byte vector."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((input (if (typep message '(simple-array (unsigned-byte 8) (*)))
                    message
                    (coerce message '(simple-array (unsigned-byte 8) (*)))))
         (padded (sha256-pad input))
         (h (make-array 8 :element-type '(unsigned-byte 32)
                        :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                            #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
         (block (make-array 64 :element-type '(unsigned-byte 8))))
    (loop for offset from 0 below (length padded) by 64
          do (replace block padded :start2 offset :end2 (+ offset 64))
             (sha256-process-block block h))
    ;; Convert to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for word = (aref h i)
            do (setf (aref result (* i 4)) (logand #xff (ash word -24))
                     (aref result (+ (* i 4) 1)) (logand #xff (ash word -16))
                     (aref result (+ (* i 4) 2)) (logand #xff (ash word -8))
                     (aref result (+ (* i 4) 3)) (logand #xff word)))
      result)))

(defun double-sha256 (message)
  "Compute SHA-256(SHA-256(message)). Used in Bitcoin."
  (sha256 (sha256 message)))

;;; ============================================================================
;;; Hex Encoding
;;; ============================================================================

(defparameter *hex-chars* "0123456789abcdef")

(defun bytes-to-hex (bytes)
  "Convert byte vector to lowercase hex string."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (optimize (speed 3) (safety 1)))
  (let* ((len (length bytes))
         (hex (make-string (* 2 len))))
    (loop for i from 0 below len
          for byte = (aref bytes i)
          do (setf (char hex (* 2 i)) (char *hex-chars* (ash byte -4))
                   (char hex (1+ (* 2 i))) (char *hex-chars* (logand byte #xf))))
    hex))

(defun sha256-hex (message)
  "Compute SHA-256 and return as hex string."
  (bytes-to-hex (sha256 message)))

(defun hex-char-value (char)
  "Convert hex char to value."
  (declare (type character char)
           (optimize (speed 3) (safety 0)))
  (cond ((char<= #\0 char #\9) (- (char-code char) (char-code #\0)))
        ((char<= #\a char #\f) (+ 10 (- (char-code char) (char-code #\a))))
        ((char<= #\A char #\F) (+ 10 (- (char-code char) (char-code #\A))))
        (t (error "Invalid hex character: ~A" char))))

(defun hex-to-bytes (hex)
  "Convert hex string to byte vector."
  (declare (type string hex)
           (optimize (speed 3) (safety 1)))
  (let* ((len (length hex))
         (bytes (make-array (/ len 2) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          do (setf (aref bytes (/ i 2))
                   (+ (ash (hex-char-value (char hex i)) 4)
                      (hex-char-value (char hex (1+ i))))))
    bytes))

;;; ============================================================================
;;; Serialization Helpers
;;; ============================================================================

(defun serialize-uint32-le (value)
  "Serialize 32-bit unsigned integer as little-endian bytes."
  (declare (type (unsigned-byte 32) value)
           (optimize (speed 3) (safety 0)))
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) (logand value #xff)
          (aref bytes 1) (logand (ash value -8) #xff)
          (aref bytes 2) (logand (ash value -16) #xff)
          (aref bytes 3) (logand (ash value -24) #xff))
    bytes))

(defun serialize-uint64-le (value)
  "Serialize 64-bit unsigned integer as little-endian bytes."
  (declare (type (unsigned-byte 64) value)
           (optimize (speed 3) (safety 0)))
  (let ((bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 8
          do (setf (aref bytes i) (logand (ash value (* -8 i)) #xff)))
    bytes))

(defun deserialize-uint32-le (bytes &optional (offset 0))
  "Deserialize 32-bit unsigned integer from little-endian bytes."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 1)))
  (logior (aref bytes offset)
          (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16)
          (ash (aref bytes (+ offset 3)) 24)))

(defun deserialize-uint64-le (bytes &optional (offset 0))
  "Deserialize 64-bit unsigned integer from little-endian bytes."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 1)))
  (loop for i from 0 below 8
        sum (ash (aref bytes (+ offset i)) (* 8 i))))

(defun serialize-varint (value)
  "Serialize variable-length integer (Bitcoin CompactSize)."
  (declare (type (unsigned-byte 64) value)
           (optimize (speed 3) (safety 1)))
  (cond ((< value #xfd)
         (make-array 1 :element-type '(unsigned-byte 8) :initial-element value))
        ((< value #x10000)
         (let ((bytes (make-array 3 :element-type '(unsigned-byte 8))))
           (setf (aref bytes 0) #xfd
                 (aref bytes 1) (logand value #xff)
                 (aref bytes 2) (logand (ash value -8) #xff))
           bytes))
        ((< value #x100000000)
         (let ((bytes (make-array 5 :element-type '(unsigned-byte 8))))
           (setf (aref bytes 0) #xfe)
           (loop for i from 1 to 4
                 do (setf (aref bytes i) (logand (ash value (* -8 (1- i))) #xff)))
           bytes))
        (t
         (let ((bytes (make-array 9 :element-type '(unsigned-byte 8))))
           (setf (aref bytes 0) #xff)
           (loop for i from 1 to 8
                 do (setf (aref bytes i) (logand (ash value (* -8 (1- i))) #xff)))
           bytes))))

(defun deserialize-varint (bytes &optional (offset 0))
  "Deserialize variable-length integer. Returns (values value bytes-consumed)."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 1)))
  (let ((first-byte (aref bytes offset)))
    (cond ((< first-byte #xfd)
           (values first-byte 1))
          ((= first-byte #xfd)
           (values (logior (aref bytes (+ offset 1))
                           (ash (aref bytes (+ offset 2)) 8))
                   3))
          ((= first-byte #xfe)
           (values (deserialize-uint32-le bytes (+ offset 1)) 5))
          (t
           (values (deserialize-uint64-le bytes (+ offset 1)) 9)))))

;;; ============================================================================
;;; Byte Vector Utilities
;;; ============================================================================

(defun concat-bytes (&rest byte-vectors)
  "Concatenate byte vectors."
  (let* ((total-len (reduce #'+ byte-vectors :key #'length))
         (result (make-array total-len :element-type '(unsigned-byte 8)))
         (offset 0))
    (dolist (vec byte-vectors result)
      (replace result vec :start1 offset)
      (incf offset (length vec)))))

(defun subseq-bytes (bytes start &optional end)
  "Extract subsequence as byte vector."
  (let* ((actual-end (or end (length bytes)))
         (result (make-array (- actual-end start) :element-type '(unsigned-byte 8))))
    (replace result bytes :start2 start :end2 actual-end)
    result))

(defun bytes-equal-p (a b)
  "Compare two byte vectors for equality."
  (and (= (length a) (length b))
       (loop for i from 0 below (length a)
             always (= (aref a i) (aref b i)))))

;;; ============================================================================
;;; Time Utilities
;;; ============================================================================

(defun unix-timestamp ()
  "Return current Unix timestamp (seconds since 1970-01-01)."
  (- (get-universal-time) 2208988800))

(defun timestamp-to-universal (timestamp)
  "Convert Unix timestamp to Lisp universal time."
  (+ timestamp 2208988800))

(defun universal-to-timestamp (universal-time)
  "Convert Lisp universal time to Unix timestamp."
  (- universal-time 2208988800))

;;; ============================================================================
;;; End of util.lisp
;;; ============================================================================
