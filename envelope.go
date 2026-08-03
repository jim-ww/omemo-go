package omemo

import "crypto/ed25519"

// KeyExchange carries the X3DH parameters needed to establish a new session.
// It is present on a RecipientKey only for the first message sent to a device
// under a given session (an OMEMOKeyExchange in XEP-0384 terms).
type KeyExchange struct {
	IdentityKey    ed25519.PublicKey
	EphemeralKey   []byte
	SignedPreKeyID uint32
	PreKeyID       uint32
}

// RecipientKey is one recipient device's wrapped copy of a message's payload
// key, encrypted through that device's own Double Ratchet session.
type RecipientKey struct {
	Device DeviceID
	Data   []byte

	// KeyExchange is set when this key was produced while establishing a new
	// session, and must accompany Data so the recipient can complete X3DH.
	KeyExchange *KeyExchange
}

// EncryptedMessage is a complete OMEMO envelope: one shared payload
// ciphertext (encrypted once) plus one wrapped key per recipient device.
//
// Payload is nil for a key-transport message, which exists only to establish
// or refresh sessions and carries no message body.
type EncryptedMessage struct {
	Sender  Device
	Keys    []RecipientKey
	Payload []byte
}
