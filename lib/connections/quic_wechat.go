// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !noquic

package connections

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	wechatVideoHeaderSize = 13
	maxQUICPacketSize     = 64 * 1024
	maxFramedPacketSize   = maxQUICPacketSize + wechatVideoHeaderSize
	packetQueueSize       = 128
	stunMagicCookie       = uint32(0x2112a442)
)

var wechatVideoHeaderTail = [...]byte{0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30}

// wechatVideoFramer owns one sequence number per sending instance. The
// sequence is only camouflage data: receivers deliberately do not require
// continuity, authenticate it, or use it for replay protection.
type wechatVideoFramer struct {
	sequence atomic.Uint32
}

func (f *wechatVideoFramer) wrap(payload []byte) []byte {
	packet := make([]byte, wechatVideoHeaderSize+len(payload))
	packet[0] = 0xa1
	packet[1] = 0x08
	binary.BigEndian.PutUint32(packet[2:6], f.sequence.Add(1))
	copy(packet[6:wechatVideoHeaderSize], wechatVideoHeaderTail[:])
	copy(packet[wechatVideoHeaderSize:], payload)
	return packet
}

func unwrapWechatVideo(packet []byte) ([]byte, bool) {
	if len(packet) < wechatVideoHeaderSize || packet[0] != 0xa1 || packet[1] != 0x08 {
		return nil, false
	}
	if !equalBytes(packet[6:wechatVideoHeaderSize], wechatVideoHeaderTail[:]) {
		return nil, false
	}
	return packet[wechatVideoHeaderSize:], true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A STUN packet has two zero high bits, a 20 byte header, the RFC 5389 magic
// cookie and a four-byte-aligned message length. Checking all of these avoids
// treating an arbitrary non-QUIC datagram as STUN based on one byte alone.
func isSTUNPacket(packet []byte) bool {
	if len(packet) < 20 || packet[0]&0xc0 != 0 || binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	return length%4 == 0 && length+20 == len(packet)
}

func isPotentialQUICPacket(packet []byte) bool {
	return len(packet) > 0 && packet[0]&0x40 != 0
}

type quicPacketMode uint8

const (
	quicPacketInvalid quicPacketMode = iota
	quicPacketStandard
	quicPacketWechat
	quicPacketSTUN
)

func classifyQUICPacket(packet []byte) quicPacketMode {
	if _, ok := unwrapWechatVideo(packet); ok {
		return quicPacketWechat
	}
	if isSTUNPacket(packet) {
		return quicPacketSTUN
	}
	if isPotentialQUICPacket(packet) {
		return quicPacketStandard
	}
	return quicPacketInvalid
}

type queuedPacket struct {
	data []byte
	addr net.Addr
}

// demuxPacketConn is a logical PacketConn backed by the one reader owned by
// quicPacketDemux. Closing it only closes its queue; it never closes the
// shared UDP socket or another mode's queue.
type demuxPacketConn struct {
	owner         *quicPacketDemux
	queue         chan queuedPacket
	done          chan struct{}
	wechatMasking bool
	framer        wechatVideoFramer

	closeOnce sync.Once
	errMu     sync.RWMutex
	err       error

	deadlineMu   sync.Mutex
	readDeadline time.Time
	readWake     chan struct{}
	writeDeadline time.Time
}

func newDemuxPacketConn(owner *quicPacketDemux, wechatMasking bool) *demuxPacketConn {
	return &demuxPacketConn{
		owner:         owner,
		queue:         make(chan queuedPacket, packetQueueSize),
		done:          make(chan struct{}),
		wechatMasking: wechatMasking,
		readWake:      make(chan struct{}),
	}
}

func (p *demuxPacketConn) enqueue(packet queuedPacket) {
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.queue <- packet:
	default:
		// A full logical queue drops the datagram. This is intentional: a
		// slow mode must not stop the single socket reader from serving the
		// other mode or STUN.
	}
}

func (p *demuxPacketConn) closeWithError(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	p.closeOnce.Do(func() {
		p.errMu.Lock()
		p.err = err
		p.errMu.Unlock()
		close(p.done)
	})
}

func (p *demuxPacketConn) terminalError() error {
	p.errMu.RLock()
	defer p.errMu.RUnlock()
	if p.err != nil {
		return p.err
	}
	return net.ErrClosed
}

func (p *demuxPacketConn) deadlines() (time.Time, <-chan struct{}) {
	p.deadlineMu.Lock()
	defer p.deadlineMu.Unlock()
	return p.readDeadline, p.readWake
}

func (p *demuxPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		deadline, wake := p.deadlines()
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, errPacketConnTimeout{}
			}
			timer = time.NewTimer(remaining)
			timerC = timer.C
		}

		select {
		case packet := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, packet.data)
			return n, packet.addr, nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, p.terminalError()
		case <-timerC:
			return 0, nil, errPacketConnTimeout{}
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (p *demuxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.deadlineMu.Lock()
	deadline := p.writeDeadline
	p.deadlineMu.Unlock()
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return 0, errPacketConnTimeout{}
	}
	select {
	case <-p.done:
		return 0, p.terminalError()
	default:
	}
	if p.wechatMasking {
		return writeWechatPacket(p.owner.conn, &p.framer, b, addr)
	}
	return p.owner.conn.WriteTo(b, addr)
}

func (p *demuxPacketConn) Close() error {
	p.closeWithError(net.ErrClosed)
	return nil
}

func (p *demuxPacketConn) LocalAddr() net.Addr {
	return p.owner.conn.LocalAddr()
}

func (p *demuxPacketConn) SetDeadline(deadline time.Time) error {
	if err := p.SetReadDeadline(deadline); err != nil {
		return err
	}
	return p.SetWriteDeadline(deadline)
}

func (p *demuxPacketConn) SetReadDeadline(deadline time.Time) error {
	p.deadlineMu.Lock()
	p.readDeadline = deadline
	oldWake := p.readWake
	p.readWake = make(chan struct{})
	close(oldWake)
	p.deadlineMu.Unlock()
	return nil
}

func (p *demuxPacketConn) SetWriteDeadline(deadline time.Time) error {
	p.deadlineMu.Lock()
	p.writeDeadline = deadline
	p.deadlineMu.Unlock()
	return nil
}

type errPacketConnTimeout struct{}

func (errPacketConnTimeout) Error() string   { return "i/o timeout" }
func (errPacketConnTimeout) Timeout() bool   { return true }
func (errPacketConnTimeout) Temporary() bool { return true }

// quicPacketDemux owns the underlying socket. quic-go explicitly requires one
// Transport per PacketConn, so the standard and masked listeners each receive
// a logical PacketConn and cannot compete for reads from the same UDP socket.
type quicPacketDemux struct {
	conn   net.PacketConn
	plain  *demuxPacketConn
	wechat *demuxPacketConn
	stun   *demuxPacketConn

	closeOnce sync.Once
}

func newQUICPacketDemux(conn net.PacketConn) *quicPacketDemux {
	d := &quicPacketDemux{conn: conn}
	d.plain = newDemuxPacketConn(d, false)
	d.wechat = newDemuxPacketConn(d, true)
	d.stun = newDemuxPacketConn(d, false)
	go d.readLoop()
	return d
}

func (d *quicPacketDemux) readLoop() {
	buffer := make([]byte, maxFramedPacketSize)
	for {
		n, addr, err := d.conn.ReadFrom(buffer)
		if err != nil {
			d.plain.closeWithError(err)
			d.wechat.closeWithError(err)
			d.stun.closeWithError(err)
			return
		}

		packet := buffer[:n]
		switch classifyQUICPacket(packet) {
		case quicPacketWechat:
			payload, _ := unwrapWechatVideo(packet)
			d.wechat.enqueue(queuedPacket{data: clonePacket(payload), addr: addr})
		case quicPacketSTUN:
			d.stun.enqueue(queuedPacket{data: clonePacket(packet), addr: addr})
		case quicPacketStandard:
			d.plain.enqueue(queuedPacket{data: clonePacket(packet), addr: addr})
		default:
			// Invalid and unclassifiable datagrams are discarded at the
			// boundary. In particular, they never reach a QUIC parser or
			// terminate the listener.
		}
	}
}

func clonePacket(packet []byte) []byte {
	copyOfPacket := make([]byte, len(packet))
	copy(copyOfPacket, packet)
	return copyOfPacket
}

func (d *quicPacketDemux) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.plain.closeWithError(net.ErrClosed)
		d.wechat.closeWithError(net.ErrClosed)
		d.stun.closeWithError(net.ErrClosed)
		err = d.conn.Close()
	})
	return err
}

// wechatPacketConn is used for a dial that cannot reuse a listener's shared
// socket. It hides UDPConn's OOB/GSO methods from quic-go and applies the
// framing at the datagram boundary, not around stream Write calls.
type wechatPacketConn struct {
	net.PacketConn
	framer wechatVideoFramer
}

func newWechatPacketConn(conn net.PacketConn) *wechatPacketConn {
	return &wechatPacketConn{PacketConn: conn}
}

var wechatReadBufferPool = sync.Pool{New: func() any {
	return make([]byte, maxFramedPacketSize)
}}

func (c *wechatPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := wechatReadBufferPool.Get().([]byte)
	defer wechatReadBufferPool.Put(buffer)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		payload, ok := unwrapWechatVideo(buffer[:n])
		if !ok {
			// A dedicated masked dialer must not silently accept standard
			// QUIC. It is safe to ignore unrelated datagrams and keep reading.
			continue
		}
		return copy(p, payload), addr, nil
	}
}

func (c *wechatPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return writeWechatPacket(c.PacketConn, &c.framer, p, addr)
}

func writeWechatPacket(conn net.PacketConn, framer *wechatVideoFramer, payload []byte, addr net.Addr) (int, error) {
	packet := framer.wrap(payload)
	n, err := conn.WriteTo(packet, addr)
	if n > wechatVideoHeaderSize {
		n -= wechatVideoHeaderSize
		if n > len(payload) {
			n = len(payload)
		}
	} else {
		n = 0
	}
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	return n, err
}

type quicTransportRegistration struct {
	transport     *quic.Transport
	wechatMasking bool
}
