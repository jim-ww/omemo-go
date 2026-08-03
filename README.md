# omemo-go

A Go implementation of [OMEMO 2](https://xmpp.org/extensions/xep-0384.html) (XEP-0384) as a
transport- and storage-independent protocol layer.

`omemo-go` owns device state, session lifecycle, bundle management and trust decisions. It builds
and parses OMEMO protocol objects and decides when X3DH/Double Ratchet operations happen, but never
implements cryptography itself - that's handled by
[`xochimilco`](https://github.com/jim-ww/xochimilco). It is not an XMPP client: you bring your own
XMPP library and storage backend.

```
XMPP client
     |
     v
 omemo-go
     |
     v
 xochimilco  (X3DH + Double Ratchet)
```

## Install

```
go get github.com/jim-ww/omemo-go
```

## Usage

Implement `omemo.Store` (persistence) and `omemo.Transport` (bundle/device-list publish and
fetch), or use `memstore.New()` to get started.

```go
ctx := context.Background()
store := memstore.New()

if err := omemo.InitIdentity(ctx, store, "alice@example.com", 1); err != nil {
    log.Fatal(err)
}

mgr, err := omemo.NewManager(ctx, store, transport,
    omemo.WithTrustResolver(func(ctx context.Context, dev omemo.Device, key ed25519.PublicKey) error {
        // Verify the fingerprint (e.g. prompt the user), or return an error
        // to refuse the device. Returning nil trusts and persists the decision.
        return nil
    }),
)
if err != nil {
    log.Fatal(err)
}

if err := mgr.PublishBundle(ctx); err != nil {
    log.Fatal(err)
}

// Encrypt for every known device of a contact. Best-effort: a failure for
// one device doesn't block the others.
msg, deviceErrs, err := mgr.EncryptMessage(ctx, "bob@example.com", []byte("hello"))
if err != nil {
    log.Fatal(err) // only set if every recipient device failed
}
// deliver msg via your own XMPP stanza-sending code

// On the receiving side, hand a parsed incoming EncryptedMessage to:
plaintext, err := mgr.DecryptMessage(ctx, msg)
```

`Manager` never sends or receives XMPP stanzas itself. `EncryptMessage`/`DecryptMessage` only
build and consume `omemo.EncryptedMessage` values; wiring those into `<message>` stanzas and
sending/receiving them is the application's job. `Transport` is only used for the bundle and
device-list exchange (e.g. XMPP PEP), which OMEMO's own state machine drives on its own schedule
(key rotation, prekey top-up, session bootstrap).

## Status

Core protocol state machine (identity/bundle/session/trust management, multi-device encrypt,
best-effort fan-out, key-transport messages) is implemented and covered by an end-to-end test in
`manager_test.go`. Not included:

- An XML (de)serialization adapter for a specific XMPP library - `Bundle`,
  `DeviceList` and `EncryptedMessage` are plain Go structs, independent of any wire format.
- A persistent `Store` implementation for production use (see `memstore` for a reference/testing
  implementation).
