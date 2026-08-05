// SPDX-FileCopyrightText: 2026 jim-ww
//
// SPDX-License-Identifier: GPL-3.0-or-later

// This file drives devtest/omemo-interop/bridge.py, a JSON-lines RPC wrapper
// around Syndace's python-omemo (twomemo + oldmemo backends) - a real,
// independently maintained implementation of both OMEMO 2 and legacy OMEMO
// deployed in production (Gajim) against Conversations/Dino. See
// xochimilco's copy of this file (and bridge.py's module docstring) for the
// full protocol reference; this is the same client duplicated for this
// separate Go module.
package omemo_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	pythonOnce sync.Once
	pythonPath string
	pythonErr  error
)

func interopPython(t *testing.T) string {
	t.Helper()

	pythonOnce.Do(func() {
		if _, err := exec.LookPath("nix"); err != nil {
			pythonErr = fmt.Errorf("nix not found in PATH: %w", err)
			return
		}

		dir, err := filepath.Abs("devtest/omemo-interop")
		if err != nil {
			pythonErr = err
			return
		}

		cmd := exec.Command("nix", "build", ".#default", "--no-link", "--print-out-paths")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			pythonErr = fmt.Errorf("nix build devtest/omemo-interop#default: %w", err)
			return
		}

		lines := strings.Fields(strings.TrimSpace(string(out)))
		if len(lines) == 0 {
			pythonErr = fmt.Errorf("nix build printed no store path")
			return
		}
		pythonPath = filepath.Join(lines[len(lines)-1], "bin", "python3")
	})

	if pythonErr != nil {
		t.Skipf("skipping OMEMO interop test, reference implementation unavailable: %v", pythonErr)
	}
	return pythonPath
}

type pyBridge struct {
	w *bufio.Writer
	r *bufio.Scanner
}

func newPyBridge(t *testing.T) *pyBridge {
	t.Helper()

	python := interopPython(t)
	dir, err := filepath.Abs("devtest/omemo-interop")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(python, "bridge.py")
	cmd.Dir = dir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("bridge stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("bridge stdout pipe: %v", err)
	}

	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting bridge.py: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	b := &pyBridge{w: bufio.NewWriter(stdin), r: scanner}

	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("bridge.py stderr:\n%s", stderr.String())
		}
	})

	return b
}

func (b *pyBridge) call(t *testing.T, req map[string]any) map[string]any {
	t.Helper()

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshaling bridge request %v: %v", req["cmd"], err)
	}
	if _, err := b.w.Write(data); err != nil {
		t.Fatalf("writing bridge request: %v", err)
	}
	if err := b.w.WriteByte('\n'); err != nil {
		t.Fatalf("writing bridge request: %v", err)
	}
	if err := b.w.Flush(); err != nil {
		t.Fatalf("flushing bridge request: %v", err)
	}

	if !b.r.Scan() {
		t.Fatalf("bridge closed unexpectedly waiting for a reply to %v: %v", req["cmd"], b.r.Err())
	}

	var resp map[string]any
	if err := json.Unmarshal(b.r.Bytes(), &resp); err != nil {
		t.Fatalf("parsing bridge response to %v: %v (raw: %s)", req["cmd"], err, b.r.Bytes())
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("bridge call %v failed: %v", req["cmd"], resp["error"])
	}
	return resp
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// optB64 encodes b as base64, or returns nil (JSON null) for an empty/nil
// slice - bridge.py distinguishes "no IV" (ProtocolV2) from an empty-but-
// present IV via None vs "", and base64-of-nil is "" not null.
func optB64(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b64(b)
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding base64 %q: %v", s, err)
	}
	return b
}

func respBytes(t *testing.T, resp map[string]any, key string) []byte {
	t.Helper()
	s, ok := resp[key].(string)
	if !ok {
		t.Fatalf("bridge response missing string field %q: %v", key, resp)
	}
	return unb64(t, s)
}

func respOptBytes(t *testing.T, resp map[string]any, key string) []byte {
	t.Helper()
	v, ok := resp[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("bridge response field %q is not a string: %v", key, v)
	}
	return unb64(t, s)
}

// frame33/unframe33 add/strip the 0x05 "DJB type" byte legacy OMEMO's wire
// format prefixes every Curve25519 public key with. omemo-go's own Bundle/
// KeyExchange types store raw (unframed) keys - the framing is a kage
// xmpp-layer (and bridge.py wire-format) concern only.
func frame33(pub []byte) []byte { return append([]byte{0x05}, pub...) }

func unframe33(t *testing.T, wire []byte) []byte {
	t.Helper()
	if len(wire) != 33 || wire[0] != 0x05 {
		t.Fatalf("public key not in 33-byte 0x05-framed wire format: % x", wire)
	}
	return wire[1:]
}
