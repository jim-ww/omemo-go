// Package memstore is a plain in-memory omemo.Store, useful for tests and as
// a reference for implementing the interface against a real database.
package memstore

import (
	"context"

	"fmt"
	"sync"

	omemo "github.com/jim-ww/omemo-go"
)

// Store is an in-memory omemo.Store. The zero value is not usable; use New.
type Store struct {
	mu sync.Mutex

	identityKey []byte
	localDevice omemo.Device

	currentSPK   omemo.SignedPreKeyRecord
	staleSPK     *omemo.SignedPreKeyRecord
	preKeys      map[uint32]omemo.PreKeyRecord
	nextPreKeyID uint32

	sessions map[omemo.Device][]byte
	trust    map[string]omemo.TrustState // keyed by identity key bytes
	devices  map[string][]omemo.DeviceID
	remoteID map[omemo.Device][]byte
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		preKeys:  make(map[uint32]omemo.PreKeyRecord),
		sessions: make(map[omemo.Device][]byte),
		trust:    make(map[string]omemo.TrustState),
		devices:  make(map[string][]omemo.DeviceID),
		remoteID: make(map[omemo.Device][]byte),
	}
}

func (s *Store) IdentityKeyPair(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identityKey, nil
}

func (s *Store) SetIdentityKeyPair(_ context.Context, priv []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityKey = priv
	return nil
}

func (s *Store) LocalDevice(context.Context) (omemo.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localDevice, nil
}

func (s *Store) SetLocalDevice(_ context.Context, dev omemo.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localDevice = dev
	return nil
}

func (s *Store) CurrentSignedPreKey(context.Context) (omemo.SignedPreKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentSPK, nil
}

func (s *Store) StaleSignedPreKey(context.Context) (omemo.SignedPreKeyRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.staleSPK == nil {
		return omemo.SignedPreKeyRecord{}, false, nil
	}
	return *s.staleSPK, true, nil
}

func (s *Store) RotateSignedPreKey(_ context.Context, next omemo.SignedPreKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentSPK.Public != nil {
		prev := s.currentSPK
		s.staleSPK = &prev
	}
	s.currentSPK = next
	return nil
}

func (s *Store) PreKeyCount(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.preKeys), nil
}

func (s *Store) PreKeys(context.Context) ([]omemo.PreKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs := make([]omemo.PreKeyRecord, 0, len(s.preKeys))
	for _, r := range s.preKeys {
		recs = append(recs, r)
	}
	return recs, nil
}

func (s *Store) NextPreKeyID(context.Context) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextPreKeyID++
	return s.nextPreKeyID, nil
}

func (s *Store) PutPreKeys(_ context.Context, recs []omemo.PreKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		s.preKeys[r.ID] = r
	}
	return nil
}

func (s *Store) ConsumePreKey(_ context.Context, id uint32) (omemo.PreKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.preKeys[id]
	if !ok {
		return omemo.PreKeyRecord{}, fmt.Errorf("one-time prekey %d not found", id)
	}
	delete(s.preKeys, id)
	return rec, nil
}

func (s *Store) Session(_ context.Context, dev omemo.Device) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.sessions[dev]
	return data, ok, nil
}

func (s *Store) PutSession(_ context.Context, dev omemo.Device, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[dev] = data
	return nil
}

func (s *Store) DeleteSession(_ context.Context, dev omemo.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, dev)
	return nil
}

func (s *Store) Trust(_ context.Context, identityKey []byte) (omemo.TrustState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trust[string(identityKey)], nil
}

func (s *Store) SetTrust(_ context.Context, identityKey []byte, state omemo.TrustState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trust[string(identityKey)] = state
	return nil
}

func (s *Store) Devices(_ context.Context, jid string) ([]omemo.DeviceID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[jid], nil
}

func (s *Store) SetDevices(_ context.Context, jid string, devices []omemo.DeviceID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[jid] = devices
	return nil
}

func (s *Store) RemoteIdentityKey(_ context.Context, dev omemo.Device) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.remoteID[dev]
	return key, ok, nil
}

func (s *Store) PutRemoteIdentityKey(_ context.Context, dev omemo.Device, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteID[dev] = key
	return nil
}

var _ omemo.Store = (*Store)(nil)
