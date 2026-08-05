package omemo

import (
	"context"
)

// SignedPreKeyRecord is a signed prekey together with its private half, as
// held by the device that published it.
type SignedPreKeyRecord struct {
	ID        uint32
	Public    []byte
	Private   []byte
	Signature []byte
}

// PreKeyRecord is a one-time prekey together with its private half, as held
// by the device that published it, before it is consumed by a peer.
type PreKeyRecord struct {
	ID      uint32
	Public  []byte
	Private []byte
}

// IdentityStore persists this device's own long-term identity.
//
// The private key's format depends on the protocol a given Store instance is
// scoped to (a Manager is scoped to exactly one Protocol - see NewManager):
// a 64-byte Ed25519 seed+public key (crypto/ed25519.PrivateKey's format) for
// ProtocolV2, or a 32-byte raw Curve25519 scalar for ProtocolV1.
type IdentityStore interface {
	IdentityKeyPair(ctx context.Context) ([]byte, error)
	SetIdentityKeyPair(ctx context.Context, priv []byte) error

	LocalDevice(ctx context.Context) (Device, error)
	SetLocalDevice(ctx context.Context, dev Device) error
}

// PreKeyStore persists this device's own signed prekey (plus a stale one kept
// during its rotation grace period) and one-time prekey pool.
type PreKeyStore interface {
	CurrentSignedPreKey(ctx context.Context) (SignedPreKeyRecord, error)
	// StaleSignedPreKey returns the previous signed prekey, if one is still
	// being kept around during its rotation grace period, and ok=false
	// otherwise.
	StaleSignedPreKey(ctx context.Context) (rec SignedPreKeyRecord, ok bool, err error)
	// RotateSignedPreKey stores next as the current signed prekey, demoting
	// the previous current one to stale.
	RotateSignedPreKey(ctx context.Context, next SignedPreKeyRecord) error

	PreKeyCount(ctx context.Context) (int, error)
	// PreKeys lists the currently unconsumed one-time prekey pool, for
	// publishing a bundle. It does not consume anything.
	PreKeys(ctx context.Context) ([]PreKeyRecord, error)
	// NextPreKeyID atomically allocates and returns the next unused one-time
	// prekey ID. It MUST never repeat an ID, including ones already consumed
	// and no longer present in the pool - the live count alone cannot be
	// used to derive this, since consumed prekeys leave no trace behind.
	NextPreKeyID(ctx context.Context) (uint32, error)
	PutPreKeys(ctx context.Context, recs []PreKeyRecord) error
	// ConsumePreKey atomically fetches and deletes a one-time prekey by ID.
	// It MUST fail if the ID is unknown or was already consumed, since OMEMO
	// forbids reusing a one-time prekey.
	ConsumePreKey(ctx context.Context, id uint32) (PreKeyRecord, error)
}

// SessionStore persists per-device Double Ratchet session state as an opaque
// blob (see internal/signal.Session.Marshal).
type SessionStore interface {
	Session(ctx context.Context, dev Device) (data []byte, ok bool, err error)
	PutSession(ctx context.Context, dev Device, data []byte) error
	DeleteSession(ctx context.Context, dev Device) error
}

// TrustStore persists trust decisions. Trust is bound to an identity key
// (its fingerprint) rather than a Device, since that key - not the device ID
// - is OMEMO's actual security anchor. identityKey bytes differ by protocol
// (see IdentityStore) but never collide across protocols since Ed25519 and
// Curve25519 keys occupy the same 32-byte space with effectively disjoint
// values, and callers additionally scope Store instances per protocol.
type TrustStore interface {
	Trust(ctx context.Context, identityKey []byte) (TrustState, error)
	SetTrust(ctx context.Context, identityKey []byte, state TrustState) error
}

// DeviceStore persists known device lists (own and contacts') and the
// identity key last seen for each remote device.
type DeviceStore interface {
	Devices(ctx context.Context, jid string) ([]DeviceID, error)
	SetDevices(ctx context.Context, jid string, devices []DeviceID) error

	RemoteIdentityKey(ctx context.Context, dev Device) (key []byte, ok bool, err error)
	PutRemoteIdentityKey(ctx context.Context, dev Device, key []byte) error
}

// Store aggregates all persistence this library needs. Implementations may
// back it with SQLite, Postgres, Badger, BoltDB, memory, or anything else.
type Store interface {
	IdentityStore
	PreKeyStore
	SessionStore
	TrustStore
	DeviceStore
}
