// Copyright (C) 2019 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !noquic

package connections

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/syncthing/syncthing/lib/osutil"
)

var quicConfig = &quic.Config{
	MaxIdleTimeout:  30 * time.Second,
	KeepAlivePeriod: 15 * time.Second,
}

func quicConfigForMode(wechatMasking bool) *quic.Config {
	if !wechatMasking {
		return quicConfig
	}

	// Keep the ordinary configuration untouched. The additional 13-byte
	// envelope is accounted for conservatively by disabling PMTU discovery
	// and using the QUIC minimum Initial size; paths must still carry the
	// resulting 1213-byte UDP payload plus outer protocol headers.
	masked := *quicConfig
	masked.InitialPacketSize = 1200
	masked.DisablePathMTUDiscovery = true
	return &masked
}

func quicNetwork(uri *url.URL) string {
	switch uri.Scheme {
	case "quic4":
		return "udp4"
	case "quic6":
		return "udp6"
	default:
		return "udp"
	}
}

type quicTlsConn struct {
	*quic.Conn
	*quic.Stream

	// If we created this connection, we should be the ones closing it.
	createdConn net.PacketConn
}

func (q *quicTlsConn) Close() error {
	sterr := q.Stream.Close()
	seerr := q.Conn.CloseWithError(0, "closing")
	var pcerr error
	if q.createdConn != nil {
		pcerr = q.createdConn.Close()
	}
	if sterr != nil {
		return sterr
	}
	if seerr != nil {
		return seerr
	}
	return pcerr
}

func (q *quicTlsConn) ConnectionState() tls.ConnectionState {
	return q.Conn.ConnectionState().TLS
}

func transportConnUnspecified(conn any) bool {
	tran, ok := conn.(*quic.Transport)
	if !ok {
		return false
	}
	addr := tran.Conn.LocalAddr()
	ip, err := osutil.IPFromAddr(addr)
	return err == nil && ip.IsUnspecified()
}

// A transportPacketConn is a net.PacketConn that uses a quic.Transport.
type transportPacketConn struct {
	tran         *quic.Transport
	readDeadline atomic.Value // time.Time
}

func (t *transportPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	ctx := context.Background()
	if deadline, ok := t.readDeadline.Load().(time.Time); ok && !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	return t.tran.ReadNonQUICPacket(ctx, p)
}

func (t *transportPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return t.tran.WriteTo(p, addr)
}

func (*transportPacketConn) Close() error {
	return errUnsupported
}

func (t *transportPacketConn) LocalAddr() net.Addr {
	return t.tran.Conn.LocalAddr()
}

func (t *transportPacketConn) SetDeadline(deadline time.Time) error {
	return t.SetReadDeadline(deadline)
}

func (t *transportPacketConn) SetReadDeadline(deadline time.Time) error {
	t.readDeadline.Store(deadline)
	return nil
}

func (*transportPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil // yolo
}
