// Package crypto provides cryptographic primitives for DataCrypt.
// This file implements secure memory handling to protect sensitive key material.
package crypto

import (
	"runtime"
	"unsafe"
)

// ZeroBytes securely overwrites a byte slice with zeros.
// Uses a volatile-style write pattern to resist compiler optimization.
// runtime.KeepAlive ensures the slice is not garbage-collected before zeroing.
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}

	// Use a pointer-based approach to resist compiler dead-store elimination
	ptr := unsafe.Pointer(&b[0])
	for i := range b {
		*(*byte)(unsafe.Add(ptr, uintptr(i))) = 0
	}

	// Prevent the GC from collecting the slice before we finish zeroing
	runtime.KeepAlive(b)
}

// ZeroSlices securely zeroes multiple byte slices.
func ZeroSlices(slices ...[]byte) {
	for _, s := range slices {
		ZeroBytes(s)
	}
}

// SecureBuffer is a byte slice wrapper that automatically zeros on cleanup.
type SecureBuffer struct {
	data []byte
}

// NewSecureBuffer allocates a new secure buffer of the given size.
func NewSecureBuffer(size int) *SecureBuffer {
	return &SecureBuffer{
		data: make([]byte, size),
	}
}

// NewSecureBufferFrom wraps an existing byte slice. The caller should not
// retain references to the original slice after this call.
func NewSecureBufferFrom(data []byte) *SecureBuffer {
	buf := &SecureBuffer{
		data: make([]byte, len(data)),
	}
	copy(buf.data, data)
	// Zero the original
	ZeroBytes(data)
	return buf
}

// Bytes returns the underlying data. The caller must not retain this reference
// after calling Destroy().
func (sb *SecureBuffer) Bytes() []byte {
	return sb.data
}

// Len returns the length of the buffer.
func (sb *SecureBuffer) Len() int {
	return len(sb.data)
}

// Destroy securely zeros the buffer contents and releases the reference.
func (sb *SecureBuffer) Destroy() {
	if sb.data != nil {
		ZeroBytes(sb.data)
		sb.data = nil
	}
}

// ConstantTimeCompare performs a constant-time comparison of two byte slices.
// Returns true if and only if the slices are equal.
// This prevents timing side-channel attacks when comparing secrets.
func ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
