package omemo

// KeyExchange carries the X3DH parameters needed to establish a new session.
// It is present on a RecipientKey only for the first message sent to a device
// under a given session (an OMEMOKeyExchange in XEP-0384 terms).
type KeyExchange struct {
	// IdentityKey is the sender's public identity key: Ed25519 for
	// ProtocolV2, Curve25519 for ProtocolV1.
	IdentityKey    []byte
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

	// IV is the payload's initialization vector. It is only set for
	// ProtocolV1 messages carrying a Payload: legacy OMEMO's payload cipher
	// (unlike ProtocolV2's) uses an explicit, non-secret IV sent in the
	// clear rather than one derived from key material inside the ratchet.
	IV []byte
}
