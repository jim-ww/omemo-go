package omemo

import (
	"context"
	"fmt"
	"sync"

	"github.com/jim-ww/omemo-go/internal/signal"
)

// DefaultPreKeyCount is how many one-time prekeys GenerateOneTimePreKeys
// generates when asked for the recommended pool size.
const DefaultPreKeyCount = 100

// MinPreKeyCount is OMEMO's minimum bundle prekey count; NeedsMorePreKeys
// reports true once the stored pool drops to or below this.
const MinPreKeyCount = 25

// Manager is the high-level OMEMO protocol state machine. It owns device,
// session, bundle and trust state, and is the only type applications need to
// call: X3DH and the Double Ratchet are never invoked directly by callers.
//
// A Manager is safe for concurrent use. Session state is guarded per remote
// device, so encrypting or decrypting for different devices proceeds
// independently.
type Manager struct {
	store     Store
	transport Transport
	protocol  Protocol

	identityKey []byte
	localDevice Device

	trustResolver TrustResolver

	locksMu sync.Mutex
	locks   map[Device]*sync.Mutex
}

// Option configures optional Manager behavior.
type Option func(*Manager)

// WithTrustResolver installs a callback consulted for recipient devices
// whose identity key has no trust decision yet. Without one, encrypting to
// such a device fails with ErrUntrustedDevice.
func WithTrustResolver(r TrustResolver) Option {
	return func(m *Manager) { m.trustResolver = r }
}

// NewManager loads this device's identity from store and returns a ready
// Manager for protocol. Call InitIdentity first if this is a fresh Store.
//
// protocol MUST match whatever protocol InitIdentity was called with for
// store - a Store is expected to be scoped to exactly one protocol (an
// account speaking both maintains two separate Store instances, one per
// protocol, each its own device identity and prekey pool).
func NewManager(ctx context.Context, store Store, transport Transport, protocol Protocol, opts ...Option) (*Manager, error) {
	idKey, err := store.IdentityKeyPair(ctx)
	if err != nil {
		return nil, fmt.Errorf("load identity key: %w", err)
	}
	dev, err := store.LocalDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("load local device: %w", err)
	}

	m := &Manager{
		store:       store,
		transport:   transport,
		protocol:    protocol,
		identityKey: idKey,
		localDevice: dev,
		locks:       make(map[Device]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// InitIdentity generates a fresh identity key pair and device ID and stores
// them, along with an initial signed prekey and one-time prekey pool. It
// MUST be called exactly once for a new Store, before NewManager, with the
// same protocol NewManager will later be called with.
func InitIdentity(ctx context.Context, store Store, jid string, deviceID DeviceID, protocol Protocol) error {
	idKey, err := signal.GenerateIdentityKey(signal.Protocol(protocol))
	if err != nil {
		return fmt.Errorf("generate identity key: %w", err)
	}
	if err := store.SetIdentityKeyPair(ctx, idKey); err != nil {
		return fmt.Errorf("store identity key: %w", err)
	}
	if err := store.SetLocalDevice(ctx, Device{JID: jid, ID: deviceID}); err != nil {
		return fmt.Errorf("store local device: %w", err)
	}

	spkPub, spkPriv, spkSig, err := signal.GenerateSignedPreKey(signal.Protocol(protocol), idKey)
	if err != nil {
		return fmt.Errorf("generate signed prekey: %w", err)
	}
	if err := store.RotateSignedPreKey(ctx, SignedPreKeyRecord{ID: 1, Public: spkPub, Private: spkPriv, Signature: spkSig}); err != nil {
		return fmt.Errorf("store signed prekey: %w", err)
	}

	return generateOneTimePreKeys(ctx, store, DefaultPreKeyCount)
}

func (m *Manager) deviceLock(dev Device) *sync.Mutex {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()

	l, ok := m.locks[dev]
	if !ok {
		l = &sync.Mutex{}
		m.locks[dev] = l
	}
	return l
}

// LocalDevice returns this Manager's own device identity.
func (m *Manager) LocalDevice() Device { return m.localDevice }

// Bundle builds this device's currently published bundle from the identity
// and prekey state held in the Store, for publishing via PublishBundle.
func (m *Manager) Bundle(ctx context.Context) (Bundle, error) {
	spk, err := m.store.CurrentSignedPreKey(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("load signed prekey: %w", err)
	}
	preKeyRecs, err := m.store.PreKeys(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("load prekeys: %w", err)
	}

	preKeys := make([]PreKey, len(preKeyRecs))
	for i, r := range preKeyRecs {
		preKeys[i] = PreKey{ID: r.ID, Public: r.Public}
	}

	pub, err := signal.IdentityPublicKey(signal.Protocol(m.protocol), m.identityKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("derive identity public key: %w", err)
	}

	return Bundle{
		Device:      m.localDevice,
		IdentityKey: pub,
		SignedPreKey: SignedPreKey{
			ID:        spk.ID,
			Public:    spk.Public,
			Signature: spk.Signature,
		},
		PreKeys: preKeys,
	}, nil
}

// PublishBundle publishes this device's current bundle via Transport.
func (m *Manager) PublishBundle(ctx context.Context) error {
	bundle, err := m.Bundle(ctx)
	if err != nil {
		return err
	}
	return m.transport.PublishBundle(ctx, bundle)
}

// RotateSignedPreKey generates a new signed prekey, demoting the current one
// to stale for its rotation grace period. OMEMO recommends doing this every
// one to four weeks; the caller decides the schedule.
func (m *Manager) RotateSignedPreKey(ctx context.Context) error {
	nextID, err := m.nextSignedPreKeyID(ctx)
	if err != nil {
		return err
	}

	spkPub, spkPriv, spkSig, err := signal.GenerateSignedPreKey(signal.Protocol(m.protocol), m.identityKey)
	if err != nil {
		return fmt.Errorf("generate signed prekey: %w", err)
	}
	return m.store.RotateSignedPreKey(ctx, SignedPreKeyRecord{ID: nextID, Public: spkPub, Private: spkPriv, Signature: spkSig})
}

func (m *Manager) nextSignedPreKeyID(ctx context.Context) (uint32, error) {
	cur, err := m.store.CurrentSignedPreKey(ctx)
	if err != nil {
		return 0, fmt.Errorf("load signed prekey: %w", err)
	}
	return cur.ID + 1, nil
}

// GenerateOneTimePreKeys generates n new one-time prekeys and adds them to
// the pool.
func (m *Manager) GenerateOneTimePreKeys(ctx context.Context, n int) error {
	return generateOneTimePreKeys(ctx, m.store, n)
}

func generateOneTimePreKeys(ctx context.Context, store PreKeyStore, n int) error {
	recs := make([]PreKeyRecord, 0, n)
	for i := 0; i < n; i++ {
		id, err := store.NextPreKeyID(ctx)
		if err != nil {
			return fmt.Errorf("allocate prekey id: %w", err)
		}
		pub, priv, err := signal.GenerateOneTimePreKey()
		if err != nil {
			return fmt.Errorf("generate one-time prekey: %w", err)
		}
		recs = append(recs, PreKeyRecord{ID: id, Public: pub, Private: priv})
	}
	return store.PutPreKeys(ctx, recs)
}

// NeedsMorePreKeys reports whether the one-time prekey pool has dropped to
// or below OMEMO's minimum bundle size and should be topped up (followed by
// PublishBundle - note the bundle itself only ever advertises the pool the
// Store holds; the caller's Transport.PublishBundle is expected to publish
// the full current pool, not just what Bundle returns).
func (m *Manager) NeedsMorePreKeys(ctx context.Context) (bool, error) {
	count, err := m.store.PreKeyCount(ctx)
	if err != nil {
		return false, fmt.Errorf("count prekeys: %w", err)
	}
	return count <= MinPreKeyCount, nil
}

// SyncDevices refreshes the known device list for jid via Transport and
// stores it.
func (m *Manager) SyncDevices(ctx context.Context, jid string) error {
	list, err := m.transport.FetchDeviceList(ctx, jid)
	if err != nil {
		return fmt.Errorf("fetch device list for %s: %w", jid, err)
	}
	return m.store.SetDevices(ctx, jid, list.Devices)
}

func (m *Manager) devicesFor(ctx context.Context, jid string) ([]DeviceID, error) {
	devices, err := m.store.Devices(ctx, jid)
	if err != nil {
		return nil, fmt.Errorf("load devices for %s: %w", jid, err)
	}
	if len(devices) > 0 {
		return devices, nil
	}
	if err := m.SyncDevices(ctx, jid); err != nil {
		return nil, err
	}
	return m.store.Devices(ctx, jid)
}

// EncryptMessage encrypts plaintext for every known device of jid, plus every
// other known device of the local account (so the sender's own other
// clients, e.g. a phone, can decrypt messages sent from this device),
// creating sessions as needed. It is best-effort: a failure for one
// recipient device does not prevent encrypting for the others. The returned
// error is non-nil only if no recipient could be encrypted for at all;
// per-device failures are always reported in the returned slice.
func (m *Manager) EncryptMessage(ctx context.Context, jid string, plaintext []byte) (*EncryptedMessage, []DeviceError, error) {
	return m.encrypt(ctx, jid, plaintext)
}

// EncryptKeyTransport builds a key-transport message: it establishes or
// refreshes sessions with every known device of jid (and the local
// account's other devices), carrying no message body. Applications
// typically send this proactively to warm sessions ahead of an actual
// message, or to recover from a broken session.
func (m *Manager) EncryptKeyTransport(ctx context.Context, jid string) (*EncryptedMessage, []DeviceError, error) {
	return m.encrypt(ctx, jid, nil)
}

// ResetSession discards any session (good or broken) held with dev, so the
// next message to or from it forces a brand-new session via a fresh X3DH
// handshake against dev's currently-published bundle, instead of continuing
// to use a session that decrypt/encrypt calls have started failing against.
// A session going bad on our end (e.g. our own session storage was wiped)
// isn't something the far side can detect on its own - it keeps sending
// ordinary ratchet messages against a session we no longer recognize, which
// DecryptMessage can only ever fail with ErrUnknownSession, forever, until
// something forces a rebuild. Callers should follow this with
// EncryptKeyTransport to dev's JID, so the far side also picks up the new
// session instead of continuing to encrypt against the one just discarded.
func (m *Manager) ResetSession(ctx context.Context, dev Device) error {
	lock := m.deviceLock(dev)
	lock.Lock()
	defer lock.Unlock()

	if err := m.store.DeleteSession(ctx, dev); err != nil {
		return fmt.Errorf("reset session for %s device %d: %w", dev.JID, dev.ID, err)
	}
	return nil
}

// recipientDevices returns jid's known devices, plus - unless jid is
// already the local account's own bare JID - the local account's other
// known devices, so a sent message can be decrypted by the sender's own
// other clients too.
func (m *Manager) recipientDevices(ctx context.Context, jid string) ([]Device, error) {
	deviceIDs, err := m.devicesFor(ctx, jid)
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(deviceIDs)+1)
	for _, id := range deviceIDs {
		devices = append(devices, Device{JID: jid, ID: id})
	}

	if jid == m.localDevice.JID {
		return devices, nil
	}
	// Best-effort: not knowing our own other devices shouldn't block sending
	// to the actual recipient, so a fetch failure here is silently ignored
	// rather than propagated.
	ownIDs, err := m.devicesFor(ctx, m.localDevice.JID)
	if err != nil {
		return devices, nil
	}
	for _, id := range ownIDs {
		devices = append(devices, Device{JID: m.localDevice.JID, ID: id})
	}
	return devices, nil
}

func (m *Manager) encrypt(ctx context.Context, jid string, plaintext []byte) (*EncryptedMessage, []DeviceError, error) {
	devices, err := m.recipientDevices(ctx, jid)
	if err != nil {
		return nil, nil, err
	}

	keyMaterial, iv, ciphertext, err := signal.EncryptPayload(signal.Protocol(m.protocol), plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt payload: %w", err)
	}
	if plaintext == nil {
		ciphertext = nil
		iv = nil
	}

	msg := &EncryptedMessage{Sender: m.localDevice, Payload: ciphertext, IV: iv}
	var deviceErrs []DeviceError

	for _, dev := range devices {
		if dev == m.localDevice {
			continue
		}

		key, err := m.encryptForDevice(ctx, dev, keyMaterial)
		if err != nil {
			deviceErrs = append(deviceErrs, DeviceError{Device: dev, Err: err})
			continue
		}
		msg.Keys = append(msg.Keys, key)
	}

	if len(msg.Keys) == 0 {
		return nil, deviceErrs, ErrNoRecipients
	}
	return msg, deviceErrs, nil
}

func (m *Manager) encryptForDevice(ctx context.Context, dev Device, keyMaterial []byte) (RecipientKey, error) {
	lock := m.deviceLock(dev)
	lock.Lock()
	defer lock.Unlock()

	sess, kx, err := m.getOrCreateActiveSession(ctx, dev)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("establish session: %w", err)
	}

	idKey, ok, err := m.store.RemoteIdentityKey(ctx, dev)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("load identity key: %w", err)
	}
	if !ok {
		return RecipientKey{}, fmt.Errorf("no known identity key for device")
	}
	if err := m.checkTrust(ctx, dev, idKey); err != nil {
		return RecipientKey{}, err
	}

	data, err := sess.Encrypt(keyMaterial)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("ratchet encrypt: %w", err)
	}
	if err := m.putSession(ctx, dev, sess); err != nil {
		return RecipientKey{}, err
	}

	return RecipientKey{Device: dev.ID, Data: data, KeyExchange: kx}, nil
}

// checkTrust enforces the trust decision for identityKey, consulting the
// configured TrustResolver for an undecided device and persisting the
// outcome. Caller MUST hold dev's device lock.
func (m *Manager) checkTrust(ctx context.Context, dev Device, identityKey []byte) error {
	state, err := m.store.Trust(ctx, identityKey)
	if err != nil {
		return fmt.Errorf("load trust state: %w", err)
	}

	switch state {
	case TrustTrusted:
		return nil
	case TrustUntrusted:
		return ErrBlockedDevice
	}

	if m.trustResolver == nil {
		return ErrUntrustedDevice
	}
	if err := m.trustResolver(ctx, dev, identityKey); err != nil {
		return err
	}
	return m.store.SetTrust(ctx, identityKey, TrustTrusted)
}

// getOrCreateActiveSession returns an existing session for dev, or
// establishes a new one by fetching dev's bundle and performing X3DH. kx is
// non-nil only when a new session was just created, and must accompany the
// first message sent under it.
func (m *Manager) getOrCreateActiveSession(ctx context.Context, dev Device) (sess *signal.Session, kx *KeyExchange, err error) {
	if data, ok, err := m.store.Session(ctx, dev); err != nil {
		return nil, nil, fmt.Errorf("load session: %w", err)
	} else if ok {
		sess, err := signal.LoadSession(signal.Protocol(m.protocol), data)
		return sess, nil, err
	}

	bundle, err := m.transport.FetchBundle(ctx, dev)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch bundle: %w", err)
	}
	if len(bundle.PreKeys) == 0 {
		return nil, nil, fmt.Errorf("peer bundle has no one-time prekeys available")
	}
	preKey := bundle.PreKeys[0]

	sess, ekPub, err := signal.NewActiveSession(
		signal.Protocol(m.protocol), m.identityKey, bundle.IdentityKey, bundle.SignedPreKey.Public, bundle.SignedPreKey.Signature, preKey.Public,
		bundle.SignedPreKey.ID, preKey.ID, uint32(m.localDevice.ID),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("X3DH: %w", err)
	}

	if err := m.store.PutRemoteIdentityKey(ctx, dev, bundle.IdentityKey); err != nil {
		return nil, nil, fmt.Errorf("store identity key: %w", err)
	}

	ownPub, err := signal.IdentityPublicKey(signal.Protocol(m.protocol), m.identityKey)
	if err != nil {
		return nil, nil, fmt.Errorf("derive identity public key: %w", err)
	}

	return sess, &KeyExchange{
		IdentityKey:    ownPub,
		EphemeralKey:   ekPub,
		SignedPreKeyID: bundle.SignedPreKey.ID,
		PreKeyID:       preKey.ID,
	}, nil
}

func (m *Manager) putSession(ctx context.Context, dev Device, sess *signal.Session) error {
	data, err := sess.Marshal()
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := m.store.PutSession(ctx, dev, data); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

// DecryptMessage decrypts an incoming EncryptedMessage. If msg carries a
// KeyExchange for this device, a new session is established as the
// responding party; otherwise an existing session is required.
//
// The returned plaintext is nil for a key-transport message.
func (m *Manager) DecryptMessage(ctx context.Context, msg *EncryptedMessage) ([]byte, error) {
	var key *RecipientKey
	for i := range msg.Keys {
		if msg.Keys[i].Device == m.localDevice.ID {
			key = &msg.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, ErrOwnDeviceKeyMissing
	}

	lock := m.deviceLock(msg.Sender)
	lock.Lock()
	defer lock.Unlock()

	sess, dataToDecrypt, err := m.getOrCreateSessionForIncoming(ctx, msg.Sender, key)
	if err != nil {
		return nil, fmt.Errorf("establish session: %w", err)
	}

	keyMaterial, err := sess.Decrypt(dataToDecrypt)
	if err != nil {
		return nil, fmt.Errorf("ratchet decrypt: %w", err)
	}
	if err := m.putSession(ctx, msg.Sender, sess); err != nil {
		return nil, err
	}

	if msg.Payload == nil {
		return nil, nil
	}
	plaintext, err := signal.DecryptPayload(signal.Protocol(m.protocol), keyMaterial, msg.IV, msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// getOrCreateSessionForIncoming returns a session ready to decrypt key.Data
// (or, for ProtocolV1 first messages, the bytes actually returned as
// dataToDecrypt - the embedded WhisperMessage, not the outer
// PreKeyWhisperMessage envelope key.Data itself is).
func (m *Manager) getOrCreateSessionForIncoming(ctx context.Context, sender Device, key *RecipientKey) (sess *signal.Session, dataToDecrypt []byte, err error) {
	if key.KeyExchange == nil {
		data, ok, err := m.store.Session(ctx, sender)
		if err != nil {
			return nil, nil, fmt.Errorf("load session: %w", err)
		}
		if !ok {
			return nil, nil, ErrUnknownSession
		}
		sess, err = signal.LoadSession(signal.Protocol(m.protocol), data)
		return sess, key.Data, err
	}

	if m.protocol == ProtocolV1 {
		signedPreKeyID, preKeyID, err := signal.PeekLegacyPreKeyIDs(key.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing legacy prekey message: %w", err)
		}
		spk, err := m.signedPreKeyByID(ctx, signedPreKeyID)
		if err != nil {
			return nil, nil, err
		}
		preKey, err := m.store.ConsumePreKey(ctx, preKeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("consume one-time prekey %d: %w", preKeyID, err)
		}

		sess, peerIdentityKey, innerData, err := signal.NewPassiveSessionFromPreKeyBlob(m.identityKey, spk.Public, spk.Private, preKey.Private, key.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("X3DH: %w", err)
		}
		if err := m.store.PutRemoteIdentityKey(ctx, sender, peerIdentityKey); err != nil {
			return nil, nil, fmt.Errorf("store identity key: %w", err)
		}
		return sess, innerData, nil
	}

	kx := key.KeyExchange
	spk, err := m.signedPreKeyByID(ctx, kx.SignedPreKeyID)
	if err != nil {
		return nil, nil, err
	}
	preKey, err := m.store.ConsumePreKey(ctx, kx.PreKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("consume one-time prekey %d: %w", kx.PreKeyID, err)
	}

	sess, err = signal.NewPassiveSession(m.identityKey, kx.IdentityKey, spk.Public, spk.Private, preKey.Private, kx.EphemeralKey)
	if err != nil {
		return nil, nil, fmt.Errorf("X3DH: %w", err)
	}

	if err := m.store.PutRemoteIdentityKey(ctx, sender, kx.IdentityKey); err != nil {
		return nil, nil, fmt.Errorf("store identity key: %w", err)
	}
	return sess, key.Data, nil
}

func (m *Manager) signedPreKeyByID(ctx context.Context, id uint32) (SignedPreKeyRecord, error) {
	cur, err := m.store.CurrentSignedPreKey(ctx)
	if err != nil {
		return SignedPreKeyRecord{}, fmt.Errorf("load signed prekey: %w", err)
	}
	if cur.ID == id {
		return cur, nil
	}

	stale, ok, err := m.store.StaleSignedPreKey(ctx)
	if err != nil {
		return SignedPreKeyRecord{}, fmt.Errorf("load stale signed prekey: %w", err)
	}
	if ok && stale.ID == id {
		return stale, nil
	}

	return SignedPreKeyRecord{}, fmt.Errorf("unknown signed prekey id %d", id)
}
