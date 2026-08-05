#!/usr/bin/env python3
"""JSON-lines RPC bridge exposing python-omemo's twomemo/oldmemo backends
(the real reference implementation, same wire format as Conversations/Dino/
Gajim) to non-Python test harnesses. One JSON object per line on stdin, one
JSON object response per line on stdout. Backends/sessions live in-process
for the lifetime of this script, keyed by ids chosen by the caller, so a Go
test can drive a multi-step handshake across several requests.

Every field that represents wire bytes travels as base64. Commands:

  new_backend      {id, protocol: "twomemo"|"oldmemo"}
  generate_bundle  {id, device_id, num_pre_keys}
                   -> {identity_key, signed_pre_key, signed_pre_key_sig,
                       pre_keys: [...], signed_pre_key_id, pre_key_ids: {b64: id}}
  build_active_session
                   {id, session, peer_jid, peer_device_id, peer_bundle: <as above>,
                    plaintext_b64}
                   -> {content_b64, iv_b64|null, key_exchange_b64}
                   (key_exchange_b64 is the full wire OMEMOKeyExchange, already
                    carrying the encrypted key material inside it - this is
                    exactly the bytes a real prekey message puts on the wire)
  build_passive_session
                   {id, session, peer_jid, peer_device_id, key_exchange_b64,
                    content_b64, iv_b64|null}
                   -> {plaintext_b64}
  encrypt          {id, session, plaintext_b64}
                   -> {content_b64, iv_b64|null, ekm_b64}
  decrypt          {id, session, peer_jid, peer_device_id, content_b64,
                     iv_b64|null, ekm_b64}
                   -> {plaintext_b64}

Every response is {"ok": true, ...} or {"ok": false, "error": "..."}.
"""
import asyncio
import base64
import json
import sys
from typing import Any, Dict

import xeddsa
import x3dh
from omemo.storage import Storage, Maybe, Just, Nothing
from omemo.types import JSONType
from x3dh.types import Bundle as X3DHBundle
import twomemo.twomemo as tm
import oldmemo.oldmemo as om

# oldmemo's X3DH math operates on the identity key as Ed25519 internally
# (python-omemo's uniform IdentityKeyPair representation, shared with
# twomemo), but the real wire format - and this bridge's contract with
# Go, which represents legacy OMEMO identities as native Curve25519 keys
# throughout, never touching Ed25519 - is the Curve25519 form with the
# Ed25519 sign bit folded into the top bit of the signature's last byte
# (see oldmemo/etree.py serialize_bundle/parse_bundle, and
# KeyExchangeImpl.serialize/parse for the equivalent per-message handling,
# which already does this conversion internally and needs no help here).
# These two helpers do for bundle bytes exactly what etree.py does, so
# every oldmemo bundle field crossing the RPC boundary is genuine wire
# bytes, not python-omemo's internal representation.


def frame(pub: bytes) -> bytes:
    return b"\x05" + pub


def unframe(wire: bytes) -> bytes:
    if len(wire) != 33 or wire[0] != 0x05:
        raise ValueError("public key not in 33-byte 0x05-framed wire format")
    return wire[1:]


def oldmemo_bundle_to_wire(b) -> Dict[str, Any]:
    sig = bytearray(b.signed_pre_key_sig)
    sig[63] |= b.identity_key[31] & 0x80
    return {
        "identity_key": b64(frame(xeddsa.ed25519_pub_to_curve25519_pub(b.identity_key))),
        "signed_pre_key": b64(frame(b.signed_pre_key)),
        "pre_keys": [b64(frame(k)) for k in b.pre_keys],
        "signed_pre_key_sig": b64(bytes(sig)),
    }


def oldmemo_bundle_from_wire(pb: Dict[str, Any]) -> X3DHBundle:
    sig = bytearray(unb64(pb["signed_pre_key_sig"]))
    sign_bit = bool((sig[63] >> 7) & 1)
    sig[63] &= 0x7F
    identity_key = xeddsa.curve25519_pub_to_ed25519_pub(unframe(unb64(pb["identity_key"])), sign_bit)
    return X3DHBundle(
        identity_key=identity_key,
        signed_pre_key=unframe(unb64(pb["signed_pre_key"])),
        signed_pre_key_sig=bytes(sig),
        pre_keys=frozenset(unframe(unb64(k)) for k in pb["pre_keys"]),
    )


class InMemoryStorage(Storage):
    def __init__(self) -> None:
        super().__init__()
        self.__data: Dict[str, JSONType] = {}

    async def _load(self, key: str) -> Maybe[JSONType]:
        try:
            return Just(self.__data[key])
        except KeyError:
            return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


BACKEND_CLASSES = {"twomemo": tm.Twomemo, "oldmemo": om.Oldmemo}
IMPL_MODULES = {"twomemo": tm, "oldmemo": om}

backends: Dict[str, Any] = {}
protocols: Dict[str, str] = {}
sessions: Dict[str, Any] = {}


def content_to_wire(content) -> Dict[str, Any]:
    iv = getattr(content, "initialization_vector", None)
    return {"content_b64": b64(content.ciphertext), "iv_b64": b64(iv) if iv is not None else None}


def content_from_wire(mod, req) -> Any:
    ciphertext = unb64(req["content_b64"])
    iv_b64 = req.get("iv_b64")
    if iv_b64 is None:
        return mod.ContentImpl(ciphertext)
    return mod.ContentImpl(ciphertext, unb64(iv_b64))


async def handle(req: Dict[str, Any]) -> Dict[str, Any]:
    cmd = req["cmd"]

    if cmd == "new_backend":
        proto = req["protocol"]
        backends[req["id"]] = BACKEND_CLASSES[proto](InMemoryStorage())
        protocols[req["id"]] = proto
        return {"ok": True}

    if cmd == "generate_bundle":
        backend = backends[req["id"]]
        await backend.generate_pre_keys(req["num_pre_keys"])
        bundle = await backend.get_bundle("test@example.org", req["device_id"])
        b = bundle.bundle
        resp = {"ok": True, "signed_pre_key_id": bundle.signed_pre_key_id}
        if protocols[req["id"]] == "oldmemo":
            resp.update(oldmemo_bundle_to_wire(b))
            resp["pre_key_ids"] = {b64(frame(k)): v for k, v in bundle.pre_key_ids.items()}
        else:
            resp["identity_key"] = b64(b.identity_key)
            resp["signed_pre_key"] = b64(b.signed_pre_key)
            resp["signed_pre_key_sig"] = b64(b.signed_pre_key_sig)
            resp["pre_keys"] = [b64(k) for k in b.pre_keys]
            resp["pre_key_ids"] = {b64(k): v for k, v in bundle.pre_key_ids.items()}
        return resp

    if cmd == "build_active_session":
        backend = backends[req["id"]]
        mod = IMPL_MODULES[protocols[req["id"]]]
        pb = req["peer_bundle"]

        if protocols[req["id"]] == "oldmemo":
            raw_bundle = oldmemo_bundle_from_wire(pb)
            pre_key_ids = {unframe(unb64(k)): v for k, v in pb["pre_key_ids"].items()}
        else:
            raw_bundle = X3DHBundle(
                identity_key=unb64(pb["identity_key"]),
                signed_pre_key=unb64(pb["signed_pre_key"]),
                signed_pre_key_sig=unb64(pb["signed_pre_key_sig"]),
                pre_keys=frozenset(unb64(k) for k in pb["pre_keys"]),
            )
            pre_key_ids = {unb64(k): v for k, v in pb["pre_key_ids"].items()}
        bundle = mod.BundleImpl(
            req["peer_jid"], req["peer_device_id"], raw_bundle,
            pb["signed_pre_key_id"], pre_key_ids,
        )

        content, pkm = await backend.encrypt_plaintext(unb64(req["plaintext_b64"]))
        session, ekm = await backend.build_session_active(
            req["peer_jid"], req["peer_device_id"], bundle, pkm
        )
        sessions[req["session"]] = session

        kex = session.key_exchange
        serialized = kex.serialize(ekm.serialize())
        if isinstance(serialized, tuple):
            kex_bytes, sign_bit = serialized
        else:
            kex_bytes, sign_bit = serialized, None

        header = kex.header
        if protocols[req["id"]] == "oldmemo":
            ik_wire = frame(xeddsa.ed25519_pub_to_curve25519_pub(header.identity_key))
            ek_wire = frame(header.ephemeral_key)
        else:
            ik_wire = header.identity_key
            ek_wire = header.ephemeral_key

        resp = {
            "ok": True,
            "key_exchange_b64": b64(kex_bytes),
            "sign_bit": sign_bit,
            # Raw key-exchange fields, for callers (like a xochimilco-level Go
            # test) that don't have a protobuf encoder/decoder for the outer
            # OMEMOKeyExchange framing handy - that assembly is a level above
            # xochimilco proper. ik/ek are always the sender's own wire-form
            # public keys (32 bytes for twomemo, 33-byte 0x05-framed for
            # oldmemo), matching what build_passive_session_raw expects back.
            "ik_b64": b64(ik_wire),
            "ek_b64": b64(ek_wire),
            "pk_id": kex.pre_key_id,
            "spk_id": kex.signed_pre_key_id,
            "ekm_b64": b64(ekm.serialize()),
        }
        resp.update(content_to_wire(content))
        return resp

    if cmd == "build_passive_session_raw":
        backend = backends[req["id"]]
        mod = IMPL_MODULES[protocols[req["id"]]]

        if protocols[req["id"]] == "oldmemo":
            ik = xeddsa.curve25519_pub_to_ed25519_pub(
                unframe(unb64(req["ik_b64"])), bool(req.get("sign_bit"))
            )
            ek = unframe(unb64(req["ek_b64"]))
        else:
            ik = unb64(req["ik_b64"])
            ek = unb64(req["ek_b64"])

        kex = mod.KeyExchangeImpl(
            x3dh.Header(ik, ek, b"", b""),
            req["spk_id"],
            req["pk_id"],
        )
        ekm = mod.EncryptedKeyMaterialImpl.parse(
            unb64(req["ekm_b64"]), req["peer_jid"], req["peer_device_id"]
        )
        session, pkm = await backend.build_session_passive(
            req["peer_jid"], req["peer_device_id"], kex, ekm
        )
        sessions[req["session"]] = session

        content = content_from_wire(mod, req)
        plaintext = await backend.decrypt_plaintext(content, pkm)
        return {"ok": True, "plaintext_b64": b64(plaintext)}

    if cmd == "build_passive_session":
        backend = backends[req["id"]]
        mod = IMPL_MODULES[protocols[req["id"]]]
        kex_bytes = unb64(req["key_exchange_b64"])

        if mod is om:
            kex, auth_msg_bytes = mod.KeyExchangeImpl.parse(kex_bytes, bool(req.get("sign_bit")))
        else:
            kex, auth_msg_bytes = mod.KeyExchangeImpl.parse(kex_bytes)

        ekm = mod.EncryptedKeyMaterialImpl.parse(auth_msg_bytes, req["peer_jid"], req["peer_device_id"])
        session, pkm = await backend.build_session_passive(
            req["peer_jid"], req["peer_device_id"], kex, ekm
        )
        sessions[req["session"]] = session

        content = content_from_wire(mod, req)
        plaintext = await backend.decrypt_plaintext(content, pkm)
        return {"ok": True, "plaintext_b64": b64(plaintext)}

    if cmd == "encrypt":
        backend = backends[req["id"]]
        session = sessions[req["session"]]
        content, pkm = await backend.encrypt_plaintext(unb64(req["plaintext_b64"]))
        ekm = await backend.encrypt_key_material(session, pkm)
        resp = {"ok": True, "ekm_b64": b64(ekm.serialize())}
        resp.update(content_to_wire(content))
        return resp

    if cmd == "decrypt":
        backend = backends[req["id"]]
        mod = IMPL_MODULES[protocols[req["id"]]]
        session = sessions[req["session"]]
        ekm = mod.EncryptedKeyMaterialImpl.parse(
            unb64(req["ekm_b64"]), req["peer_jid"], req["peer_device_id"]
        )
        pkm = await backend.decrypt_key_material(session, ekm)
        content = content_from_wire(mod, req)
        plaintext = await backend.decrypt_plaintext(content, pkm)
        return {"ok": True, "plaintext_b64": b64(plaintext)}

    raise ValueError(f"unknown cmd {cmd!r}")


async def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        try:
            resp = await handle(req)
        except Exception as e:  # noqa: BLE001
            resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
