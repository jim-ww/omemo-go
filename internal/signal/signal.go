// Package signal isolates every call into the xochimilco Signal-protocol
// backend (X3DH + Double Ratchet) behind a small, OMEMO-shaped seam.
//
// Nothing outside this package imports xochimilco directly. That keeps the
// cryptographic engine swappable in principle and keeps the rest of omemo-go
// talking only in terms of identity keys, bundles and sessions rather than
// raw X3DH/ratchet primitives.
package signal

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/jim-ww/xochimilco"
	"github.com/jim-ww/xochimilco/doubleratchet"
	"github.com/jim-ww/xochimilco/x3dh"
)

// GenerateIdentityKey creates a new long-term Ed25519 identity key pair.
func GenerateIdentityKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// GenerateSignedPreKey creates a new X25519 signed prekey, signed by idKey.
func GenerateSignedPreKey(idKey ed25519.PrivateKey) (pub, priv, sig []byte, err error) {
	return x3dh.CreateNewSpk(idKey)
}

// GenerateOneTimePreKey creates a new X25519 one-time prekey.
func GenerateOneTimePreKey() (pub, priv []byte, err error) {
	return x3dh.CreateNewOpk()
}

// Session wraps an established Double Ratchet session between the local
// device and exactly one remote device.
type Session struct {
	dr *doubleratchet.DoubleRatchet
}

// NewActiveSession starts a session as the initiating party, performing X3DH
// against a peer's published bundle material. It returns the ephemeral public
// key that MUST be sent to the peer as part of the key exchange.
func NewActiveSession(
	idKey ed25519.PrivateKey, peerIdKey ed25519.PublicKey, peerSpkPub, peerSpkSig, peerOpkPub []byte,
) (sess *Session, ekPub []byte, err error) {
	sessKey, associatedData, ekPub, err := x3dh.CreateInitialMessage(idKey, peerIdKey, peerSpkPub, peerSpkSig, peerOpkPub)
	if err != nil {
		return nil, nil, fmt.Errorf("X3DH initial message: %w", err)
	}

	dr, err := doubleratchet.CreateActive(sessKey, associatedData, peerSpkPub)
	if err != nil {
		return nil, nil, fmt.Errorf("create active ratchet: %w", err)
	}

	return &Session{dr: dr}, ekPub, nil
}

// NewPassiveSession completes a session as the responding party, using the
// local SPK/OPK key pair a peer's key exchange claims to have used.
func NewPassiveSession(
	idKey ed25519.PrivateKey, peerIdKey ed25519.PublicKey, spkPub, spkPriv, opkPriv, ekPub []byte,
) (*Session, error) {
	sessKey, associatedData, err := x3dh.ReceiveInitialMessage(idKey, peerIdKey, spkPriv, opkPriv, ekPub)
	if err != nil {
		return nil, fmt.Errorf("X3DH receive initial message: %w", err)
	}

	dr, err := doubleratchet.CreatePassive(sessKey, associatedData, spkPub, spkPriv)
	if err != nil {
		return nil, fmt.Errorf("create passive ratchet: %w", err)
	}

	return &Session{dr: dr}, nil
}

// LoadSession restores a session previously produced by Session.Marshal.
func LoadSession(data []byte) (*Session, error) {
	dr := &doubleratchet.DoubleRatchet{}
	if err := dr.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("restore ratchet state: %w", err)
	}
	return &Session{dr: dr}, nil
}

// Marshal serializes this session for persistence.
func (s *Session) Marshal() ([]byte, error) {
	return s.dr.MarshalBinary()
}

// Encrypt wraps keyMaterial (a payload key and its authentication tag, see
// EncryptPayload) through this session's ratchet, for one recipient device.
func (s *Session) Encrypt(keyMaterial []byte) ([]byte, error) {
	return s.dr.Encrypt(keyMaterial)
}

// Decrypt recovers the key material this session's peer wrapped for us.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	return s.dr.Decrypt(ciphertext)
}

// EncryptPayload encrypts plaintext once with a fresh random key, as OMEMO's
// message body encryption demands. The returned key material is then wrapped
// per-recipient-device via each device's Session.Encrypt; the ciphertext is
// shared verbatim across all recipients of the same message.
//
// A nil plaintext is used for key-transport messages, which carry no message
// body; only the key material is produced, and the ciphertext MUST be
// discarded rather than transmitted.
func EncryptPayload(plaintext []byte) (keyMaterial, ciphertext []byte, err error) {
	return xochimilco.EncryptPayload(plaintext)
}

// DecryptPayload recovers the plaintext from a shared payload ciphertext,
// given the key material recovered via this recipient device's
// Session.Decrypt.
func DecryptPayload(keyMaterial, ciphertext []byte) ([]byte, error) {
	return xochimilco.DecryptPayload(keyMaterial, ciphertext)
}
