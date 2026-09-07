// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !noquic

package connections

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestWechatVideoFramer(t *testing.T) {
	framer := new(wechatVideoFramer)
	payload := []byte("one QUIC datagram")
	original := append([]byte(nil), payload...)
	packet := framer.wrap(payload)

	if got, want := len(packet), wechatVideoHeaderSize+len(payload); got != want {
		t.Fatalf("wrapped length = %d, want %d", got, want)
	}
	if packet[0] != 0xa1 || packet[1] != 0x08 || !equalBytes(packet[6:13], wechatVideoHeaderTail[:]) {
		t.Fatalf("unexpected header: %x", packet[:wechatVideoHeaderSize])
	}
	if got := binary.BigEndian.Uint32(packet[2:6]); got != 1 {
		t.Fatalf("first sequence = %d, want 1", got)
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("wrapping modified the caller's payload")
	}
	if unwrapped, ok := unwrapWechatVideo(packet); !ok || !bytes.Equal(unwrapped, payload) {
		t.Fatalf("unwrap = %x, %v; want %x, true", unwrapped, ok, payload)
	}

	if empty, ok := unwrapWechatVideo(framer.wrap(nil)); !ok || len(empty) != 0 {
		t.Fatalf("empty payload unwrap = %x, %v", empty, ok)
	}
	for _, short := range [][]byte{nil, {0xa1}, make([]byte, wechatVideoHeaderSize - 1)} {
		if _, ok := unwrapWechatVideo(short); ok {
			t.Fatalf("short packet %x was accepted", short)
		}
	}
}

func TestWechatVideoFramerConcurrentSequence(t *testing.T) {
	const count = 128
	framer := new(wechatVideoFramer)
	sequences := make(chan uint32, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			sequences <- binary.BigEndian.Uint32(framer.wrap(nil)[2:6])
		})
	}
	wg.Wait()
	close(sequences)

	seen := make(map[uint32]struct{}, count)
	for sequence := range sequences {
		if _, ok := seen[sequence]; ok {
			t.Fatalf("duplicate sequence %d", sequence)
		}
		seen[sequence] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("got %d unique sequences, want %d", len(seen), count)
	}
}

func TestQUICPacketClassification(t *testing.T) {
	standard := []byte{0xc0, 0x00, 0x00, 0x00}
	if got := classifyQUICPacket(standard); got != quicPacketStandard {
		t.Fatalf("standard packet classified as %v", got)
	}

	stun := make([]byte, 20)
	stun[0] = 0x00
	binary.BigEndian.PutUint32(stun[4:8], stunMagicCookie)
	if got := classifyQUICPacket(stun); got != quicPacketSTUN || !isSTUNPacket(stun) {
		t.Fatalf("STUN packet classified as %v", got)
	}

	masked := (&wechatVideoFramer{}).wrap(standard)
	if got := classifyQUICPacket(masked); got != quicPacketWechat {
		t.Fatalf("masked packet classified as %v", got)
	}
	if got := classifyQUICPacket([]byte{0x00, 0x01}); got != quicPacketInvalid {
		t.Fatalf("invalid packet classified as %v", got)
	}
}

func TestWechatPacketConnDatagramSemantics(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientRaw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	client := newWechatPacketConn(clientRaw)

	payload := []byte("payload")
	n, err := client.WriteTo(payload, server.LocalAddr())
	if err != nil || n != len(payload) {
		t.Fatalf("WriteTo = %d, %v; want %d, nil", n, err, len(payload))
	}
	wire := make([]byte, 128)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, addr, err := server.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || n != len(payload)+wechatVideoHeaderSize {
		t.Fatalf("wire ReadFrom = %d, %v; want %d and address", n, addr, len(payload)+wechatVideoHeaderSize)
	}
	if decoded, ok := unwrapWechatVideo(wire[:n]); !ok || !bytes.Equal(decoded, payload) {
		t.Fatalf("wire payload = %x, %v; want %x, true", decoded, ok, payload)
	}

	response := (&wechatVideoFramer{}).wrap([]byte("response"))
	if _, err := server.WriteTo(response, clientRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	clientRaw.SetReadDeadline(time.Now().Add(time.Second))
	readBuffer := make([]byte, 128)
	n, addr, err = client.ReadFrom(readBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || string(readBuffer[:n]) != "response" {
		t.Fatalf("ReadFrom = %d, %v, %q", n, addr, readBuffer[:n])
	}
}

func TestQUICPacketDemuxAndLogicalClose(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	demux := newQUICPacketDemux(server)
	defer demux.Close()

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	plain := []byte{0xc0, 0x01, 0x02}
	masked := (&wechatVideoFramer{}).wrap([]byte{0xc0, 0x03})
	stun := make([]byte, 20)
	binary.BigEndian.PutUint32(stun[4:8], stunMagicCookie)
	for _, packet := range [][]byte{{0x00, 0x01}, plain, masked, stun} {
		if _, err := sender.WriteTo(packet, server.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	buffer := make([]byte, 128)
	demux.plain.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := demux.plain.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], plain) {
		t.Fatalf("plain demux = %d, %v, %x", n, err, buffer[:n])
	}
	demux.wechat.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = demux.wechat.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], []byte{0xc0, 0x03}) {
		t.Fatalf("masked demux = %d, %v, %x", n, err, buffer[:n])
	}
	demux.stun.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = demux.stun.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], stun) {
		t.Fatalf("STUN demux = %d, %v, %x", n, err, buffer[:n])
	}
	stunResponse := append([]byte(nil), stun...)
	if _, err := demux.stun.WriteTo(stunResponse, sender.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	sender.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = sender.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], stunResponse) {
		t.Fatalf("STUN reverse path = %d, %v, %x", n, err, buffer[:n])
	}

	if err := demux.plain.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing one logical queue must not close the shared UDP socket or the
	// other mode's queue.
	if _, err := sender.WriteTo(masked, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	demux.wechat.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := demux.wechat.ReadFrom(buffer); err != nil || n != 2 {
		t.Fatalf("masked queue after plain close = %d, %v", n, err)
	}
}

func TestWechatVideoQUICConnection(t *testing.T) {
	withConnectionPairMode(t, "quic4://127.0.0.1:0", true, func(client, server internalConn) {
		if !client.isQUICWechat() || !server.isQUICWechat() {
			t.Fatalf("connection modes = %s, %s; want masked QUIC", client.Type(), server.Type())
		}
		payload := []byte("masked QUIC payload")
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if n, err := io.ReadFull(server, received); err != nil || n != len(payload) || !bytes.Equal(received, payload) {
			t.Fatalf("received = %d, %v, %q", n, err, received)
		}
	})
}
