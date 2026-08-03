// Package omemo implements the OMEMO 2 protocol (XEP-0384) as a transport-
// and storage-independent orchestration layer on top of a Signal-protocol
// backend. It builds and parses OMEMO protocol objects, manages device,
// session, bundle and trust state, and decides when cryptographic operations
// happen - it never implements cryptography itself.
package omemo

import "crypto/ed25519"

// DeviceID identifies a single OMEMO device belonging to some JID.
type DeviceID uint32

// Device identifies one specific OMEMO-capable client instance.
type Device struct {
	JID string
	ID  DeviceID
}

// SignedPreKey is the public half of a bundle's signed prekey, rotated
// periodically (OMEMO recommends every one to four weeks).
type SignedPreKey struct {
	ID        uint32
	Public    []byte
	Signature []byte
}

// PreKey is the public half of a single one-time prekey offered in a bundle.
// OMEMO demands a bundle carry at least 25, recommended around 100.
type PreKey struct {
	ID     uint32
	Public []byte
}

// Bundle is a device's published X3DH key material, as fetched from or
// published to whatever transport (e.g. XMPP PEP) the application provides.
type Bundle struct {
	Device       Device
	IdentityKey  ed25519.PublicKey
	SignedPreKey SignedPreKey

	// PreKeys is the pool a bundle publisher offers; a consumer establishing
	// a session picks exactly one and the publisher MUST NOT reuse it.
	PreKeys []PreKey
}

// DeviceList is the set of active device IDs known for a JID.
type DeviceList struct {
	JID     string
	Devices []DeviceID
}

// TrustState describes the trust decision associated with a remote device's
// identity key.
type TrustState int

const (
	// TrustUndecided means no trust decision has been made yet. Encrypting to
	// such a device is refused unless a TrustResolver is configured.
	TrustUndecided TrustState = iota

	// TrustTrusted means the identity key has been verified or accepted.
	TrustTrusted

	// TrustUntrusted means the identity key has been explicitly rejected
	// (e.g. it changed unexpectedly). Such a device is always skipped.
	TrustUntrusted
)

func (s TrustState) String() string {
	switch s {
	case TrustTrusted:
		return "trusted"
	case TrustUntrusted:
		return "untrusted"
	default:
		return "undecided"
	}
}
