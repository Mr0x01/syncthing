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
	"errors"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/syncthing/syncthing/internal/slogutil"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/connections/registry"
	"github.com/syncthing/syncthing/lib/nat"
	"github.com/syncthing/syncthing/lib/stun"
	"github.com/syncthing/syncthing/lib/svcutil"
)

func init() {
	factory := &quicListenerFactory{}
	for _, scheme := range []string{"quic", "quic4", "quic6"} {
		listeners[scheme] = factory
	}
}

type quicListener struct {
	svcutil.ServiceWithError
	onAddressesChangedNotifier

	nat atomic.Uint64 // Holds a stun.NATType.

	uri        *url.URL
	cfg        config.Wrapper
	tlsCfg     *tls.Config
	conns      chan internalConn
	factory    listenerFactory
	registry   *registry.Registry
	lanChecker *lanChecker

	address    *url.URL
	natService *nat.Service
	mapping    *nat.Mapping
	laddr      net.Addr
	mut        sync.Mutex
}

func (t *quicListener) OnNATTypeChanged(natType stun.NATType) {
	if natType != stun.NATUnknown {
		slog.Info("Detected NAT type", slogutil.URI(t.uri), slog.Any("type", natType))
	}
	t.nat.Store(uint64(natType))
}

func (t *quicListener) OnExternalAddressChanged(address *stun.Host, via string) {
	var uri *url.URL
	if address != nil {
		copy := *t.uri
		uri = &copy
		uri.Host = address.TransportAddr()
	}

	t.mut.Lock()
	existingAddress := t.address
	t.address = uri
	t.mut.Unlock()

	if uri != nil && (existingAddress == nil || existingAddress.String() != uri.String()) {
		slog.Info("Resolved external address", slogutil.URI(t.uri), slogutil.Address(uri.String()), slog.String("via", via))
		t.notifyAddressesChanged(t)
	} else if uri == nil && existingAddress != nil {
		t.notifyAddressesChanged(t)
	}
}

func (t *quicListener) serve(ctx context.Context) error {
	network := quicNetwork(t.uri)

	udpAddr, err := net.ResolveUDPAddr(network, t.uri.Host)
	if err != nil {
		slog.WarnContext(ctx, "Failed to listen (QUIC)", slogutil.Error(err))
		return err
	}

	udpConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		slog.WarnContext(ctx, "Failed to listen (QUIC)", slogutil.Error(err))
		return err
	}
	defer udpConn.Close()

	// A single demux owns reads from udpConn. quic-go documents that a
	// PacketConn may only be passed to one Transport, so standard and masked
	// QUIC each get a logical PacketConn and Transport below.
	demux := newQUICPacketDemux(udpConn)
	plainTransport := &quic.Transport{Conn: demux.plain}
	wechatTransport := &quic.Transport{Conn: demux.wechat}
	plainListener, err := plainTransport.Listen(t.tlsCfg, quicConfigForMode(false))
	if err != nil {
		_ = demux.Close()
		slog.WarnContext(ctx, "Failed to listen (QUIC)", slogutil.Error(err))
		return err
	}
	wechatListener, err := wechatTransport.Listen(t.tlsCfg, quicConfigForMode(true))
	if err != nil {
		_ = plainListener.Close()
		_ = plainTransport.Close()
		_ = demux.Close()
		slog.WarnContext(ctx, "Failed to listen (QUIC with WeChat masking)", slogutil.Error(err))
		return err
	}

	stunCtx, cancelSTUN := context.WithCancel(ctx)
	stunDone := make(chan struct{})
	go func() {
		defer close(stunDone)
		_ = stun.New(t.cfg, t, demux.stun).Serve(stunCtx)
	}()

	plainRegistration := &quicTransportRegistration{transport: plainTransport}
	wechatRegistration := &quicTransportRegistration{transport: wechatTransport, wechatMasking: true}
	t.registry.Register(t.uri.Scheme, plainRegistration)
	defer t.registry.Unregister(t.uri.Scheme, plainRegistration)
	t.registry.Register(t.uri.Scheme, wechatRegistration)
	defer t.registry.Unregister(t.uri.Scheme, wechatRegistration)

	t.notifyAddressesChanged(t)
	defer t.clearAddresses(t)

	slog.InfoContext(ctx, "QUIC listener starting", slogutil.Address(udpConn.LocalAddr()))
	defer slog.InfoContext(ctx, "QUIC listener shutting down", slogutil.Address(udpConn.LocalAddr()))

	var ipVersion nat.IPVersion
	switch t.uri.Scheme {
	case "quic4":
		ipVersion = nat.IPv4Only
	case "quic6":
		ipVersion = nat.IPv6Only
	default:
		ipVersion = nat.IPvAny
	}
	mapping := t.natService.NewMapping(nat.UDP, ipVersion, udpAddr.IP, udpAddr.Port)
	mapping.OnChanged(func() {
		t.notifyAddressesChanged(t)
	})
	// Should be called after t.mapping is nil'ed out.
	defer t.natService.RemoveMapping(mapping)

	t.mut.Lock()
	t.mapping = mapping
	t.laddr = udpConn.LocalAddr()
	t.mut.Unlock()
	defer func() {
		t.mut.Lock()
		t.laddr = nil
		t.mut.Unlock()
	}()

	acceptCtx, stopAccept := context.WithCancel(ctx)
	acceptResults := make(chan quicAcceptResult, 2)
	var acceptWG sync.WaitGroup
	acceptWG.Add(2)
	go func() {
		defer acceptWG.Done()
		acceptQUICSessions(acceptCtx, plainListener, false, acceptResults)
	}()
	go func() {
		defer acceptWG.Done()
		acceptQUICSessions(acceptCtx, wechatListener, true, acceptResults)
	}()
	defer func() {
		stopAccept()
		cancelSTUN()
		_ = plainListener.Close()
		_ = wechatListener.Close()
		_ = plainTransport.Close()
		_ = wechatTransport.Close()
		_ = demux.Close()
		acceptWG.Wait()
		<-stunDone
	}()

	for {
		var result quicAcceptResult
		select {
		case <-ctx.Done():
			return nil
		case result = <-acceptResults:
		}
		if result.err != nil {
			if errors.Is(result.err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			slog.WarnContext(ctx, "Failed to accept QUIC connection", slogutil.Error(result.err))
			return result.err
		}

		session := result.session
		slog.DebugContext(ctx, "Incoming connection", "from", session.RemoteAddr(), "type", connTypeForQUIC(result.wechatMasking, false).String())

		streamCtx, cancel := context.WithTimeout(ctx, quicOperationTimeout)
		stream, err := session.AcceptStream(streamCtx)
		cancel()
		if err != nil {
			slog.DebugContext(ctx, "Failed to accept stream", slogutil.Address(session.RemoteAddr()), slogutil.Error(err))
			_ = session.CloseWithError(1, err.Error())
			continue
		}

		priority := t.cfg.Options().ConnectionPriorityQUICWAN
		isLocal := t.lanChecker.isLAN(session.RemoteAddr())
		if isLocal {
			priority = t.cfg.Options().ConnectionPriorityQUICLAN
		}
		connType := connTypeForQUIC(result.wechatMasking, false)
		conn := newInternalConn(&quicTlsConn{session, stream, nil}, connType, isLocal, priority)
		select {
		case t.conns <- conn:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

type quicAcceptResult struct {
	session       *quic.Conn
	wechatMasking bool
	err           error
}

func acceptQUICSessions(ctx context.Context, listener *quic.Listener, wechatMasking bool, results chan<- quicAcceptResult) {
	for {
		session, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case results <- quicAcceptResult{err: err}:
			case <-ctx.Done():
			}
			return
		}
		select {
		case results <- quicAcceptResult{session: session, wechatMasking: wechatMasking}:
		case <-ctx.Done():
			_ = session.CloseWithError(0, "listener shutting down")
			return
		}
	}
}

func connTypeForQUIC(wechatMasking, client bool) connType {
	switch {
	case wechatMasking && client:
		return connTypeQUICWechatClient
	case wechatMasking:
		return connTypeQUICWechatServer
	case client:
		return connTypeQUICClient
	default:
		return connTypeQUICServer
	}
}

func (t *quicListener) URI() *url.URL {
	return t.uri
}

func (t *quicListener) WANAddresses() []*url.URL {
	t.mut.Lock()
	uris := []*url.URL{maybeReplacePort(t.uri, t.laddr)}
	if t.address != nil {
		uris = append(uris, t.address)
	}

	uris = append(uris, portMappingURIs(t.mapping, *t.uri)...)

	t.mut.Unlock()
	return uris
}

func (t *quicListener) LANAddresses() []*url.URL {
	t.mut.Lock()
	uri := maybeReplacePort(t.uri, t.laddr)
	t.mut.Unlock()
	addrs := []*url.URL{uri}
	network := quicNetwork(uri)
	addrs = append(addrs, getURLsForAllAdaptersIfUnspecified(network, uri)...)
	return addrs
}

func (t *quicListener) String() string {
	return t.uri.String()
}

func (t *quicListener) Factory() listenerFactory {
	return t.factory
}

func (t *quicListener) NATType() string {
	v := stun.NATType(t.nat.Load())
	if v == stun.NATUnknown || v == stun.NATError {
		return "unknown"
	}
	return v.String()
}

type quicListenerFactory struct{}

func (*quicListenerFactory) Valid(config.Configuration) error {
	return nil
}

func (f *quicListenerFactory) New(uri *url.URL, cfg config.Wrapper, tlsCfg *tls.Config, conns chan internalConn, natService *nat.Service, registry *registry.Registry, lanChecker *lanChecker) genericListener {
	l := &quicListener{
		uri:        fixupPort(uri, config.DefaultQUICPort),
		cfg:        cfg,
		tlsCfg:     tlsCfg,
		conns:      conns,
		natService: natService,
		factory:    f,
		registry:   registry,
		lanChecker: lanChecker,
	}
	l.ServiceWithError = svcutil.AsService(l.serve, l.String())
	l.nat.Store(uint64(stun.NATUnknown))
	return l
}

func (quicListenerFactory) Enabled(_ config.Configuration) bool {
	return true
}
