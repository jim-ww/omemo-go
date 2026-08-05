// SPDX-FileCopyrightText: 2026 jim-ww
//
// SPDX-License-Identifier: GPL-3.0-or-later

package omemo_test

import (
	"bytes"
	"context"
	"testing"

	omemo "github.com/jim-ww/omemo-go"
	"github.com/jim-ww/omemo-go/memstore"
)

// interopFakeTransport serves canned bundles/device lists constructed from a
// bridge.py reference-implementation peer, and records what Publish* calls
// receive so the reverse direction can hand them back to the bridge.
type interopFakeTransport struct {
	bundles     map[omemo.Device]omemo.Bundle
	deviceLists map[string]omemo.DeviceList

	publishedBundle *omemo.Bundle
}

func (ft *interopFakeTransport) FetchDeviceList(_ context.Context, jid string) (omemo.DeviceList, error) {
	return ft.deviceLists[jid], nil
}
func (ft *interopFakeTransport) PublishDeviceList(context.Context, omemo.DeviceList) error { return nil }
func (ft *interopFakeTransport) FetchBundle(_ context.Context, dev omemo.Device) (omemo.Bundle, error) {
	return ft.bundles[dev], nil
}
func (ft *interopFakeTransport) PublishBundle(_ context.Context, b omemo.Bundle) error {
	ft.publishedBundle = &b
	return nil
}

func alwaysTrust(context.Context, omemo.Device, []byte) error { return nil }

func newManager(t *testing.T, jid string, protocol omemo.Protocol, transport omemo.Transport) *omemo.Manager {
	t.Helper()
	store := memstore.New()
	if err := omemo.InitIdentity(context.Background(), store, jid, 1, protocol); err != nil {
		t.Fatalf("InitIdentity: %v", err)
	}
	mgr, err := omemo.NewManager(context.Background(), store, transport, protocol, omemo.WithTrustResolver(alwaysTrust))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// pythonBundleToGo converts a bridge.py generate_bundle response into an
// omemo.Bundle, unframing wire-form Curve25519 keys for oldmemo (omemo-go's
// Bundle always stores raw keys - framing is a wire-layer concern only).
func pythonBundleToGo(t *testing.T, dev omemo.Device, protocol omemo.Protocol, resp map[string]any) omemo.Bundle {
	t.Helper()

	unwrap := func(b []byte) []byte { return b }
	if protocol == omemo.ProtocolV1 {
		unwrap = func(b []byte) []byte { return unframe33(t, b) }
	}

	preKeys, ok := resp["pre_keys"].([]any)
	if !ok || len(preKeys) == 0 {
		t.Fatalf("bundle has no pre_keys: %v", resp)
	}
	preKeyIDs, ok := resp["pre_key_ids"].(map[string]any)
	if !ok {
		t.Fatalf("bundle has no pre_key_ids: %v", resp)
	}

	pks := make([]omemo.PreKey, len(preKeys))
	for i, pk := range preKeys {
		s := pk.(string)
		pks[i] = omemo.PreKey{ID: uint32(preKeyIDs[s].(float64)), Public: unwrap(unb64(t, s))}
	}

	return omemo.Bundle{
		Device:      dev,
		IdentityKey: unwrap(respBytes(t, resp, "identity_key")),
		SignedPreKey: omemo.SignedPreKey{
			ID:        uint32(resp["signed_pre_key_id"].(float64)),
			Public:    unwrap(respBytes(t, resp, "signed_pre_key")),
			Signature: respBytes(t, resp, "signed_pre_key_sig"),
		},
		PreKeys: pks,
	}
}

// goBundleToPython converts an omemo.Bundle into generate_bundle-shaped
// wire-form JSON fields for use as build_active_session's peer_bundle,
// framing raw keys for oldmemo the way bridge.py expects.
func goBundleToPython(protocol omemo.Protocol, b omemo.Bundle) map[string]any {
	frame := func(k []byte) []byte { return k }
	if protocol == omemo.ProtocolV1 {
		frame = frame33
	}

	preKeys := make([]string, len(b.PreKeys))
	preKeyIDs := map[string]any{}
	for i, pk := range b.PreKeys {
		w := b64(frame(pk.Public))
		preKeys[i] = w
		preKeyIDs[w] = pk.ID
	}

	return map[string]any{
		"identity_key":       b64(frame(b.IdentityKey)),
		"signed_pre_key":     b64(frame(b.SignedPreKey.Public)),
		"signed_pre_key_sig": b64(b.SignedPreKey.Signature),
		"pre_keys":           preKeys,
		"signed_pre_key_id":  b.SignedPreKey.ID,
		"pre_key_ids":        preKeyIDs,
	}
}

func testInteropGoActivePythonPassive(t *testing.T, protocol, pyProtocol string, gp omemo.Protocol) {
	bridge := newPyBridge(t)
	bridge.call(t, map[string]any{"cmd": "new_backend", "id": "bob", "protocol": pyProtocol})
	bundleResp := bridge.call(t, map[string]any{
		"cmd": "generate_bundle", "id": "bob", "device_id": 1, "num_pre_keys": 5,
	})

	bobDev := omemo.Device{JID: "bob@example.org", ID: 1}
	transport := &interopFakeTransport{
		bundles:     map[omemo.Device]omemo.Bundle{bobDev: pythonBundleToGo(t, bobDev, gp, bundleResp)},
		deviceLists: map[string]omemo.DeviceList{"bob@example.org": {JID: "bob@example.org", Devices: []omemo.DeviceID{1}}},
	}
	alice := newManager(t, "alice@example.org", gp, transport)

	plaintext := []byte("hello bob, from omemo-go's " + protocol + " Manager")
	encMsg, deviceErrs, err := alice.EncryptMessage(context.Background(), "bob@example.org", plaintext)
	if err != nil {
		t.Fatalf("EncryptMessage: %v (device errors: %v)", err, deviceErrs)
	}
	if len(deviceErrs) != 0 {
		t.Fatalf("unexpected per-device errors: %v", deviceErrs)
	}
	if len(encMsg.Keys) != 1 {
		t.Fatalf("EncryptedMessage.Keys = %d entries, want 1", len(encMsg.Keys))
	}
	key := encMsg.Keys[0]

	var passive map[string]any
	if gp == omemo.ProtocolV1 {
		passive = bridge.call(t, map[string]any{
			"cmd": "build_passive_session", "id": "bob", "session": "bob_sess",
			"peer_jid": "alice@example.org", "peer_device_id": 1,
			"key_exchange_b64": b64(key.Data),
			"content_b64":       b64(encMsg.Payload),
			"iv_b64":            optB64(encMsg.IV),
		})
	} else {
		kx := key.KeyExchange
		if kx == nil {
			t.Fatalf("first message under a new session must carry a KeyExchange")
		}
		passive = bridge.call(t, map[string]any{
			"cmd": "build_passive_session_raw", "id": "bob", "session": "bob_sess",
			"peer_jid": "alice@example.org", "peer_device_id": 1,
			"ik_b64": b64(kx.IdentityKey), "ek_b64": b64(kx.EphemeralKey),
			"pk_id": kx.PreKeyID, "spk_id": kx.SignedPreKeyID,
			"ekm_b64":     b64(key.Data),
			"content_b64": b64(encMsg.Payload),
		})
	}
	gotPlaintext := respBytes(t, passive, "plaintext_b64")
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("real %s decrypted %q, want %q", protocol, gotPlaintext, plaintext)
	}

	// Established-session reply, bob (python) -> alice (go).
	reply := []byte("hi alice, from real " + protocol)
	encReply := bridge.call(t, map[string]any{
		"cmd": "encrypt", "id": "bob", "session": "bob_sess", "plaintext_b64": b64(reply),
	})
	replyMsg := &omemo.EncryptedMessage{
		Sender:  bobDev,
		Keys:    []omemo.RecipientKey{{Device: 1, Data: respBytes(t, encReply, "ekm_b64")}},
		Payload: respBytes(t, encReply, "content_b64"),
		IV:      respOptBytes(t, encReply, "iv_b64"),
	}
	gotReply, err := alice.DecryptMessage(context.Background(), replyMsg)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("alice decrypted %q, want %q", gotReply, reply)
	}
}

func TestInteropOldmemoGoActivePythonPassive(t *testing.T) {
	testInteropGoActivePythonPassive(t, "oldmemo", "oldmemo", omemo.ProtocolV1)
}

func TestInteropTwomemoGoActivePythonPassive(t *testing.T) {
	testInteropGoActivePythonPassive(t, "twomemo", "twomemo", omemo.ProtocolV2)
}

func testInteropPythonActiveGoPassive(t *testing.T, protocol, pyProtocol string, gp omemo.Protocol) {
	bobTransport := &interopFakeTransport{}
	bob := newManager(t, "bob@example.org", gp, bobTransport)
	if err := bob.GenerateOneTimePreKeys(context.Background(), 5); err != nil {
		t.Fatalf("GenerateOneTimePreKeys: %v", err)
	}
	bundle, err := bob.Bundle(context.Background())
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	bridge := newPyBridge(t)
	bridge.call(t, map[string]any{"cmd": "new_backend", "id": "alice", "protocol": pyProtocol})

	plaintext := []byte("hello bob, from real " + protocol + " (active)")
	active := bridge.call(t, map[string]any{
		"cmd": "build_active_session", "id": "alice", "session": "alice_sess",
		"peer_jid": "bob@example.org", "peer_device_id": 1,
		"peer_bundle":   goBundleToPython(gp, bundle),
		"plaintext_b64": b64(plaintext),
	})

	aliceDev := omemo.Device{JID: "alice@example.org", ID: 1}
	// KeyExchange must be set for both protocols: getOrCreateSessionForIncoming
	// uses its presence (not protocol) to decide whether this is a brand new
	// session to establish rather than a continuation of an existing one. For
	// ProtocolV1 the metadata inside it is redundant with what's already
	// self-describing in data, but it still must be non-nil.
	unwrapKx := func(b []byte) []byte { return b }
	if gp == omemo.ProtocolV1 {
		unwrapKx = func(b []byte) []byte { return unframe33(t, b) }
	}
	kx := &omemo.KeyExchange{
		IdentityKey:    unwrapKx(respBytes(t, active, "ik_b64")),
		EphemeralKey:   unwrapKx(respBytes(t, active, "ek_b64")),
		SignedPreKeyID: uint32(active["spk_id"].(float64)),
		PreKeyID:       uint32(active["pk_id"].(float64)),
	}
	var data []byte
	if gp == omemo.ProtocolV1 {
		data = respBytes(t, active, "key_exchange_b64")
	} else {
		data = respBytes(t, active, "ekm_b64")
	}
	msg := &omemo.EncryptedMessage{
		Sender:  aliceDev,
		Keys:    []omemo.RecipientKey{{Device: 1, Data: data, KeyExchange: kx}},
		Payload: respBytes(t, active, "content_b64"),
		IV:      respOptBytes(t, active, "iv_b64"),
	}

	gotPlaintext, err := bob.DecryptMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("go decrypted %q, want %q", gotPlaintext, plaintext)
	}

	// Established-session reply, bob (go) -> alice (python).
	reply := []byte("hi alice, from go")
	bobTransport.deviceLists = map[string]omemo.DeviceList{"alice@example.org": {JID: "alice@example.org", Devices: []omemo.DeviceID{1}}}
	replyMsg, deviceErrs, err := bob.EncryptMessage(context.Background(), "alice@example.org", reply)
	if err != nil {
		t.Fatalf("EncryptMessage: %v (device errors: %v)", err, deviceErrs)
	}
	if len(replyMsg.Keys) != 1 {
		t.Fatalf("EncryptedMessage.Keys = %d entries, want 1", len(replyMsg.Keys))
	}

	decReply := bridge.call(t, map[string]any{
		"cmd": "decrypt", "id": "alice", "session": "alice_sess",
		"peer_jid": "bob@example.org", "peer_device_id": 1,
		"ekm_b64": b64(replyMsg.Keys[0].Data), "content_b64": b64(replyMsg.Payload), "iv_b64": optB64(replyMsg.IV),
	})
	gotReply := respBytes(t, decReply, "plaintext_b64")
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("real %s decrypted %q, want %q", protocol, gotReply, reply)
	}
}

func TestInteropOldmemoPythonActiveGoPassive(t *testing.T) {
	testInteropPythonActiveGoPassive(t, "oldmemo", "oldmemo", omemo.ProtocolV1)
}

func TestInteropTwomemoPythonActiveGoPassive(t *testing.T) {
	testInteropPythonActiveGoPassive(t, "twomemo", "twomemo", omemo.ProtocolV2)
}
