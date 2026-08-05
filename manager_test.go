package omemo_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	omemo "github.com/jim-ww/omemo-go"
	"github.com/jim-ww/omemo-go/memstore"
)

// fakeNetwork is a shared in-memory stand-in for XMPP PEP: it holds published
// device lists and bundles that every fakeTransport reads from and writes to.
type fakeNetwork struct {
	mu      sync.Mutex
	devices map[string]omemo.DeviceList
	bundles map[omemo.Device]omemo.Bundle
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{
		devices: make(map[string]omemo.DeviceList),
		bundles: make(map[omemo.Device]omemo.Bundle),
	}
}

type fakeTransport struct{ net *fakeNetwork }

func (t fakeTransport) FetchDeviceList(_ context.Context, jid string) (omemo.DeviceList, error) {
	t.net.mu.Lock()
	defer t.net.mu.Unlock()
	list, ok := t.net.devices[jid]
	if !ok {
		return omemo.DeviceList{}, errors.New("no device list published for " + jid)
	}
	return list, nil
}

func (t fakeTransport) PublishDeviceList(_ context.Context, list omemo.DeviceList) error {
	t.net.mu.Lock()
	defer t.net.mu.Unlock()
	t.net.devices[list.JID] = list
	return nil
}

func (t fakeTransport) FetchBundle(_ context.Context, dev omemo.Device) (omemo.Bundle, error) {
	t.net.mu.Lock()
	defer t.net.mu.Unlock()
	b, ok := t.net.bundles[dev]
	if !ok {
		return omemo.Bundle{}, errors.New("no bundle published for device")
	}
	return b, nil
}

func (t fakeTransport) PublishBundle(_ context.Context, bundle omemo.Bundle) error {
	t.net.mu.Lock()
	defer t.net.mu.Unlock()
	t.net.bundles[bundle.Device] = bundle
	return nil
}

// protocols is every omemo.Protocol this test file exercises.
var protocols = []omemo.Protocol{omemo.ProtocolV2, omemo.ProtocolV1}

// setup creates a Manager for jid/deviceID speaking protocol, sharing net,
// with all recipient devices auto-trusted so tests can focus on the
// encrypt/decrypt flow.
func setup(t *testing.T, ctx context.Context, net *fakeNetwork, jid string, deviceID omemo.DeviceID, protocol omemo.Protocol) *omemo.Manager {
	t.Helper()

	store := memstore.New()
	if err := omemo.InitIdentity(ctx, store, jid, deviceID, protocol); err != nil {
		t.Fatalf("InitIdentity: %v", err)
	}

	mgr, err := omemo.NewManager(ctx, store, fakeTransport{net: net}, protocol, omemo.WithTrustResolver(
		func(context.Context, omemo.Device, []byte) error { return nil },
	))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if err := mgr.PublishBundle(ctx); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}
	if err := (fakeTransport{net: net}).PublishDeviceList(ctx, omemo.DeviceList{JID: jid, Devices: []omemo.DeviceID{deviceID}}); err != nil {
		t.Fatalf("PublishDeviceList: %v", err)
	}

	return mgr
}

func TestEndToEndConversation(t *testing.T) {
	for _, protocol := range protocols {
		t.Run(protocol.String(), func(t *testing.T) { testEndToEndConversation(t, protocol) })
	}
}

func testEndToEndConversation(t *testing.T, protocol omemo.Protocol) {
	ctx := context.Background()
	net := newFakeNetwork()

	alice := setup(t, ctx, net, "alice@example.com", 1, protocol)
	bob := setup(t, ctx, net, "bob@example.com", 1, protocol)

	// Alice's first message to Bob establishes a new session.
	msg, devErrs, err := alice.EncryptMessage(ctx, "bob@example.com", []byte("hello bob"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if len(devErrs) != 0 {
		t.Fatalf("unexpected device errors: %v", devErrs)
	}
	if len(msg.Keys) != 1 || msg.Keys[0].KeyExchange == nil {
		t.Fatalf("expected exactly one recipient key carrying a KeyExchange, got %+v", msg.Keys)
	}

	plaintext, err := bob.DecryptMessage(ctx, msg)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(plaintext) != "hello bob" {
		t.Fatalf("got %q", plaintext)
	}

	// Bob's reply reuses the now-established session; no new KeyExchange.
	reply, devErrs, err := bob.EncryptMessage(ctx, "alice@example.com", []byte("hi alice"))
	if err != nil {
		t.Fatalf("EncryptMessage (reply): %v", err)
	}
	if len(devErrs) != 0 {
		t.Fatalf("unexpected device errors: %v", devErrs)
	}
	if len(reply.Keys) != 1 || reply.Keys[0].KeyExchange != nil {
		t.Fatalf("expected reply to reuse the session without a KeyExchange, got %+v", reply.Keys)
	}

	plaintext, err = alice.DecryptMessage(ctx, reply)
	if err != nil {
		t.Fatalf("DecryptMessage (reply): %v", err)
	}
	if string(plaintext) != "hi alice" {
		t.Fatalf("got %q", plaintext)
	}

	// A second message from Alice to Bob reuses the same session.
	if _, _, err := alice.EncryptMessage(ctx, "bob@example.com", []byte("second message")); err != nil {
		t.Fatalf("EncryptMessage (second): %v", err)
	}
}

func TestKeyTransport(t *testing.T) {
	for _, protocol := range protocols {
		t.Run(protocol.String(), func(t *testing.T) { testKeyTransport(t, protocol) })
	}
}

func testKeyTransport(t *testing.T, protocol omemo.Protocol) {
	ctx := context.Background()
	net := newFakeNetwork()

	alice := setup(t, ctx, net, "alice@example.com", 1, protocol)
	bob := setup(t, ctx, net, "bob@example.com", 1, protocol)

	msg, devErrs, err := alice.EncryptKeyTransport(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("EncryptKeyTransport: %v", err)
	}
	if len(devErrs) != 0 {
		t.Fatalf("unexpected device errors: %v", devErrs)
	}
	if msg.Payload != nil {
		t.Fatalf("key-transport message must carry no payload, got %v", msg.Payload)
	}

	plaintext, err := bob.DecryptMessage(ctx, msg)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if plaintext != nil {
		t.Fatalf("key-transport message should decrypt to nil plaintext, got %q", plaintext)
	}
}

func TestUntrustedDeviceIsSkipped(t *testing.T) {
	for _, protocol := range protocols {
		t.Run(protocol.String(), func(t *testing.T) { testUntrustedDeviceIsSkipped(t, protocol) })
	}
}

func testUntrustedDeviceIsSkipped(t *testing.T, protocol omemo.Protocol) {
	ctx := context.Background()
	net := newFakeNetwork()

	store := memstore.New()
	if err := omemo.InitIdentity(ctx, store, "alice@example.com", 1, protocol); err != nil {
		t.Fatalf("InitIdentity: %v", err)
	}
	// No TrustResolver configured: any undecided device must be refused.
	alice, err := omemo.NewManager(ctx, store, fakeTransport{net: net}, protocol)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := alice.PublishBundle(ctx); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	bob := setup(t, ctx, net, "bob@example.com", 1, protocol)
	_ = bob

	_, devErrs, err := alice.EncryptMessage(ctx, "bob@example.com", []byte("hi"))
	if !errors.Is(err, omemo.ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
	if len(devErrs) != 1 || !errors.Is(devErrs[0].Err, omemo.ErrUntrustedDevice) {
		t.Fatalf("expected one ErrUntrustedDevice, got %v", devErrs)
	}
}
