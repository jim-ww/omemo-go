package omemo

import (
	"context"
	"errors"
	"fmt"
)

// ErrUntrustedDevice is returned for a recipient device whose identity key
// has no trust decision (TrustUndecided) and no TrustResolver is configured,
// or whose resolver declined it.
var ErrUntrustedDevice = errors.New("omemo: device is untrusted")

// ErrBlockedDevice is returned for a recipient device explicitly marked
// TrustUntrusted; such a device is always skipped regardless of a resolver.
var ErrBlockedDevice = errors.New("omemo: device is blocked")

// ErrNoRecipients is returned by EncryptMessage when every recipient device
// failed, so no message could be produced at all.
var ErrNoRecipients = errors.New("omemo: no recipient device could be encrypted for")

// ErrUnknownSession is returned by DecryptMessage when an incoming message
// carries no KeyExchange but no session for its sender device exists.
var ErrUnknownSession = errors.New("omemo: no session for sender device")

// ErrOwnDeviceKeyMissing is returned by DecryptMessage when an incoming
// message carries no RecipientKey for the local device.
var ErrOwnDeviceKeyMissing = errors.New("omemo: message has no key for this device")

// TrustResolver is consulted for a recipient device in TrustUndecided state.
// Returning nil trusts the device for this call and persists that decision;
// returning an error skips the device for this call without persisting
// anything, leaving it TrustUndecided for future calls.
type TrustResolver func(ctx context.Context, dev Device, identityKey []byte) error

// DeviceError reports a per-recipient-device failure during a best-effort
// multi-device operation such as EncryptMessage.
type DeviceError struct {
	Device Device
	Err    error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("device %s/%d: %v", e.Device.JID, e.Device.ID, e.Err)
}

func (e *DeviceError) Unwrap() error { return e.Err }
