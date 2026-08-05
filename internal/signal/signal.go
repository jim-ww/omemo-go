// Package signal isolates every call into the xochimilco Signal-protocol
// backend (X3DH + Double Ratchet) behind a small, OMEMO-shaped seam.
//
// Nothing outside this package imports xochimilco directly. That keeps the
// cryptographic engine swappable in principle and keeps the rest of omemo-go
// talking only in terms of identity keys, bundles and sessions rather than
// raw X3DH/ratchet primitives.
//
// Every function here is dispatched on a Protocol: ProtocolV2 (XEP-0384,
// Ed25519 identity keys, xochimilco/x3dh+doubleratchet's own protobuf wire
// format) or ProtocolV1 (legacy eu.siacs.conversations.axolotl, native
// Curve25519 identity keys signed via XEdDSA, xochimilco/legacysignal's
// libsignal-compatible wire format - a different protobuf schema, message
// framing and MAC construction, not just a config variant of ProtocolV2's).
package signal

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/jim-ww/xochimilco"
	"github.com/jim-ww/xochimilco/doubleratchet"
	"github.com/jim-ww/xochimilco/legacysignal"
	"github.com/jim-ww/xochimilco/x3dh"
)

// Protocol mirrors omemo.Protocol; duplicated here (rather than imported) to
// avoid a cycle, since the omemo package imports this one. Callers convert
// with a plain type conversion: signal.Protocol(protocol).
type Protocol int

const (
	ProtocolV2 Protocol = iota
	ProtocolV1
)

// GenerateIdentityKey creates a new long-term identity key pair: a 64-byte
// Ed25519 seed+public key (crypto/ed25519.PrivateKey's format) for
// ProtocolV2, or a 32-byte raw Curve25519 scalar for ProtocolV1.
func GenerateIdentityKey(protocol Protocol) ([]byte, error) {
	switch protocol {
	case ProtocolV1:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv.Bytes(), nil
	default:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return []byte(priv), err
	}
}

// IdentityPublicKey derives the public half of priv, as returned by
// GenerateIdentityKey for the same protocol.
func IdentityPublicKey(protocol Protocol, priv []byte) ([]byte, error) {
	switch protocol {
	case ProtocolV1:
		p, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("parsing curve25519 private key: %w", err)
		}
		return p.PublicKey().Bytes(), nil
	default:
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 private key MUST be of %d bytes", ed25519.PrivateKeySize)
		}
		return []byte(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)), nil
	}
}

// GenerateSignedPreKey creates a new X25519 signed prekey, signed by idKey
// (per protocol's signature scheme: plain Ed25519 for ProtocolV2, XEdDSA
// over the native Curve25519 key, serialized per legacysignal's wire
// convention, for ProtocolV1).
func GenerateSignedPreKey(protocol Protocol, idKey []byte) (pub, priv, sig []byte, err error) {
	if protocol == ProtocolV1 {
		return legacysignal.CreateNewSpk(idKey)
	}
	return x3dh.CreateNewSpk(ed25519.PrivateKey(idKey))
}

// GenerateOneTimePreKey creates a new X25519 one-time prekey. Identical for
// both protocols.
func GenerateOneTimePreKey() (pub, priv []byte, err error) {
	return x3dh.CreateNewOpk()
}

// legacyPendingPreKey is the state NewActiveSession (ProtocolV1) stashes so
// the first Encrypt call automatically wraps as a PreKeyWhisperMessage
// (bundling the X3DH parameters the recipient needs) rather than a plain
// WhisperMessage.
type legacyPendingPreKey struct {
	ekPub          []byte
	preKeyID       uint32
	signedPreKeyID uint32
	registrationID uint32
}

// Session wraps an established Double Ratchet session between the local
// device and exactly one remote device.
type Session struct {
	protocol Protocol

	dr *doubleratchet.DoubleRatchet // ProtocolV2
	ls *legacysignal.Session        // ProtocolV1

	pending *legacyPendingPreKey // ProtocolV1 only, cleared after first Encrypt
}

// NewActiveSession starts a session as the initiating party, performing X3DH
// against a peer's published bundle material. It returns the ephemeral public
// key that MUST be sent to the peer as part of the key exchange.
//
// peerSignedPreKeyID/peerPreKeyID/registrationID are only used for
// ProtocolV1, where they must be embedded in the first message's
// PreKeyWhisperMessage rather than carried as separate wire attributes (see
// xmpp/omemo_v1.go); ProtocolV2 callers may pass zero values.
func NewActiveSession(
	protocol Protocol, idKey, peerIdKey, peerSpkPub, peerSpkSig, peerOpkPub []byte,
	peerSignedPreKeyID, peerPreKeyID, registrationID uint32,
) (sess *Session, ekPub []byte, err error) {
	if protocol == ProtocolV1 {
		x3dhSess, ekPub, err := legacysignal.CreateInitialMessage(idKey, peerIdKey, peerSpkPub, peerSpkSig, peerOpkPub)
		if err != nil {
			return nil, nil, fmt.Errorf("X3DH initial message: %w", err)
		}
		ls, err := legacysignal.NewActiveSession(idKey, peerIdKey, x3dhSess)
		if err != nil {
			return nil, nil, fmt.Errorf("create active session: %w", err)
		}
		return &Session{
			protocol: ProtocolV1,
			ls:       ls,
			pending: &legacyPendingPreKey{
				ekPub:          ekPub,
				preKeyID:       peerPreKeyID,
				signedPreKeyID: peerSignedPreKeyID,
				registrationID: registrationID,
			},
		}, ekPub, nil
	}

	sessKey, associatedData, ekPub, err := x3dh.CreateInitialMessage(ed25519.PrivateKey(idKey), ed25519.PublicKey(peerIdKey), peerSpkPub, peerSpkSig, peerOpkPub)
	if err != nil {
		return nil, nil, fmt.Errorf("X3DH initial message: %w", err)
	}
	dr, err := doubleratchet.CreateActive(sessKey, associatedData, peerSpkPub)
	if err != nil {
		return nil, nil, fmt.Errorf("create active ratchet: %w", err)
	}
	return &Session{protocol: ProtocolV2, dr: dr}, ekPub, nil
}

// NewPassiveSession completes a ProtocolV2 session as the responding party,
// using the local SPK/OPK key pair a peer's key exchange claims to have
// used. ProtocolV1 uses NewPassiveSessionFromPreKeyBlob instead, since its
// key-exchange parameters are embedded in the message bytes rather than
// carried as separate wire attributes.
func NewPassiveSession(
	idKey, peerIdKey, spkPub, spkPriv, opkPriv, ekPub []byte,
) (*Session, error) {
	sessKey, associatedData, err := x3dh.ReceiveInitialMessage(ed25519.PrivateKey(idKey), ed25519.PublicKey(peerIdKey), spkPriv, opkPriv, ekPub)
	if err != nil {
		return nil, fmt.Errorf("X3DH receive initial message: %w", err)
	}
	dr, err := doubleratchet.CreatePassive(sessKey, associatedData, spkPub, spkPriv)
	if err != nil {
		return nil, fmt.Errorf("create passive ratchet: %w", err)
	}
	return &Session{protocol: ProtocolV2, dr: dr}, nil
}

// PeekLegacyPreKeyIDs extracts the SignedPreKeyID/PreKeyID a ProtocolV1
// <key prekey="true"/> element's bytes reference, so the caller can look up
// its own local prekey records before constructing the session via
// NewPassiveSessionFromPreKeyBlob.
func PeekLegacyPreKeyIDs(data []byte) (signedPreKeyID, preKeyID uint32, err error) {
	pm, err := legacysignal.ParsePreKeyMessage(data)
	if err != nil {
		return 0, 0, err
	}
	return pm.SignedPreKeyID, pm.PreKeyID, nil
}

// NewPassiveSessionFromPreKeyBlob completes a ProtocolV1 session as the
// responding party. data is the full <key prekey="true"/> element's bytes
// (a serialized PreKeyWhisperMessage); the caller must already have looked
// up the local spk/opk records referenced by PeekLegacyPreKeyIDs. Besides
// the session, it returns the sender's identity key (for the caller to
// cache) and the embedded message bytes to pass to Session.Decrypt.
func NewPassiveSessionFromPreKeyBlob(idKey, spkPub, spkPriv, opkPriv, data []byte) (sess *Session, peerIdentityKey, innerData []byte, err error) {
	pm, err := legacysignal.ParsePreKeyMessage(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing legacy prekey message: %w", err)
	}
	x3dhSess, err := legacysignal.ReceiveInitialMessage(idKey, pm.IdentityKey, spkPub, spkPriv, opkPriv, pm.BaseKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("X3DH receive initial message: %w", err)
	}
	ls, err := legacysignal.NewPassiveSession(idKey, pm.IdentityKey, x3dhSess)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create passive session: %w", err)
	}
	return &Session{protocol: ProtocolV1, ls: ls}, pm.IdentityKey, pm.Message, nil
}

// LoadSession restores a session previously produced by Session.Marshal.
func LoadSession(protocol Protocol, data []byte) (*Session, error) {
	if protocol == ProtocolV1 {
		ls := &legacysignal.Session{}
		if err := ls.UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("restore legacy session state: %w", err)
		}
		return &Session{protocol: ProtocolV1, ls: ls}, nil
	}
	dr := &doubleratchet.DoubleRatchet{}
	if err := dr.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("restore ratchet state: %w", err)
	}
	return &Session{protocol: ProtocolV2, dr: dr}, nil
}

// Marshal serializes this session for persistence.
func (s *Session) Marshal() ([]byte, error) {
	if s.protocol == ProtocolV1 {
		return s.ls.MarshalBinary()
	}
	return s.dr.MarshalBinary()
}

// Encrypt wraps keyMaterial (a payload key and its authentication tag, see
// EncryptPayload) through this session's ratchet, for one recipient device.
//
// For ProtocolV1, the first call after NewActiveSession automatically wraps
// the result as a PreKeyWhisperMessage instead of a plain WhisperMessage,
// consuming the pending state NewActiveSession stashed.
func (s *Session) Encrypt(keyMaterial []byte) ([]byte, error) {
	if s.protocol == ProtocolV1 {
		if s.pending != nil {
			p := s.pending
			s.pending = nil
			return legacysignal.EncryptPreKeyWhisperMessage(s.ls, keyMaterial, p.ekPub, p.preKeyID, p.signedPreKeyID, p.registrationID)
		}
		return s.ls.EncryptWhisperMessage(keyMaterial)
	}
	return s.dr.Encrypt(keyMaterial)
}

// Decrypt recovers the key material this session's peer wrapped for us.
// For ProtocolV1, data MUST already be the embedded WhisperMessage bytes
// (NewPassiveSessionFromPreKeyBlob's innerData return), not the outer
// PreKeyWhisperMessage - the caller unwraps that layer itself since it also
// needs the identity/prekey-id fields inside it to construct the session in
// the first place.
func (s *Session) Decrypt(data []byte) ([]byte, error) {
	if s.protocol == ProtocolV1 {
		return s.ls.DecryptWhisperMessage(data)
	}
	return s.dr.Decrypt(data)
}

// EncryptPayload encrypts plaintext once with a fresh random key, as OMEMO's
// message body encryption demands. The returned key material is then wrapped
// per-recipient-device via each device's Session.Encrypt; the ciphertext is
// shared verbatim across all recipients of the same message.
//
// iv is only set (and only meaningful) for ProtocolV1: legacy OMEMO's payload
// cipher uses an explicit, non-secret IV sent alongside the ciphertext rather
// than one derived from key material inside the ratchet.
//
// A nil plaintext is used for key-transport messages, which carry no message
// body; only the key material is produced, and the ciphertext MUST be
// discarded rather than transmitted.
func EncryptPayload(protocol Protocol, plaintext []byte) (keyMaterial, iv, ciphertext []byte, err error) {
	if protocol == ProtocolV1 {
		keyMaterial, iv, ciphertext, err = xochimilco.EncryptPayloadV1(plaintext)
		return
	}
	keyMaterial, ciphertext, err = xochimilco.EncryptPayload(plaintext)
	return
}

// DecryptPayload recovers the plaintext from a shared payload ciphertext,
// given the key material recovered via this recipient device's
// Session.Decrypt. iv is required (and only used) for ProtocolV1.
func DecryptPayload(protocol Protocol, keyMaterial, iv, ciphertext []byte) ([]byte, error) {
	if protocol == ProtocolV1 {
		return xochimilco.DecryptPayloadV1(keyMaterial, iv, ciphertext)
	}
	return xochimilco.DecryptPayload(keyMaterial, ciphertext)
}
