package exampleutil

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/examples/internal/socks5"
)

const (
	InternalCIDR        = "192.168.168.0/24"
	ServerPrefix        = "192.168.168.1/24"
	ClientPrefix        = "192.168.168.2/24"
	HTTPAddress         = "192.168.168.1:80"
	EgressSOCKS5Address = "192.168.168.1:1080"
	DefaultSOCKS5       = "127.0.0.1:1080"
)

var internalNetwork = netip.MustParsePrefix(InternalCIDR)

var exampleTrafficPolicy = mustExampleTrafficPolicy()

func mustExampleTrafficPolicy() govpn.TrafficPolicy {
	policy, err := govpn.NewRuleTrafficPolicy(govpn.TrafficActionAllow, []govpn.TrafficRule{
		{
			Name:             "block-example-com",
			Action:           govpn.TrafficActionDeny,
			Directions:       []govpn.TrafficDirection{govpn.TrafficDirectionServerEgress},
			DestinationHosts: []string{"example.com", "*.example.com"},
		}, {
			Name:       "block-cisco-opendns",
			Action:     govpn.TrafficActionDeny,
			Directions: []govpn.TrafficDirection{govpn.TrafficDirectionServerEgress},
			DestinationPrefixes: []netip.Prefix{
				netip.MustParsePrefix("208.67.220.220/32"),
				netip.MustParsePrefix("208.67.222.222/32"),
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return policy
}

// ExampleTrafficPolicy returns the shared server-example blacklist.
func ExampleTrafficPolicy() govpn.TrafficPolicy { return exampleTrafficPolicy }

// LogTrafficDecision records denied flows without logging every allowed packet.
func LogTrafficDecision(event govpn.TrafficPolicyEvent) {
	if event.Decision.Allowed() {
		return
	}
	log.Printf(
		"[traffic-policy] action=%s protocol=%s direction=%s source=%s:%d destination=%s:%d host=%q rule=%q reason=%q",
		event.Decision.Action, event.Flow.VPNProtocol, event.Flow.Direction,
		event.Flow.SourceIP, event.Flow.SourcePort, event.Flow.DestinationIP,
		event.Flow.DestinationPort, event.Flow.DestinationHost,
		event.Decision.Rule, event.Decision.Reason,
	)
}

type Session interface {
	socks5.Dialer
	Listen(network, address string) (net.Listener, error)
}

type ServerSession interface {
	Session
	EvaluateTraffic(govpn.TrafficFlow) govpn.TrafficDecision
	DialEgressContext(context.Context, string, string, net.Addr) (net.Conn, error)
}

func Context() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return ctx
}

func ServeServer(ctx context.Context, session ServerSession) error {
	httpListener, err := session.Listen("tcp", HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen HTTP service: %w", err)
	}
	egressListener, err := session.Listen("tcp", EgressSOCKS5Address)
	if err != nil {
		_ = httpListener.Close()
		return fmt.Errorf("listen egress SOCKS5 service: %w", err)
	}
	defer httpListener.Close()
	defer egressListener.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = httpListener.Close()
		_ = egressListener.Close()
	})
	defer stop()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("HTTP service listening inside VPN on http://%s/", HTTPAddress)
	results := make(chan error, 2)
	go func() {
		handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = response.Write([]byte("VPN works!"))
		})
		results <- (&http.Server{Handler: handler}).Serve(httpListener)
	}()
	go func() {
		results <- socks5.Serve(ctx, egressListener, &policyDialer{session: session}, logger)
	}()
	err = <-results
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type policyDialer struct {
	session ServerSession
}

func (d *policyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.session.DialEgressContext(ctx, network, address, nil)
}

func (d *policyDialer) DialRequestContext(ctx context.Context, network, address string, source net.Addr) (net.Conn, error) {
	connection, err := d.session.DialEgressContext(ctx, network, address, source)
	if errors.Is(err, govpn.ErrTrafficDenied) {
		return nil, fmt.Errorf("%w: %s", socks5.ErrConnectionNotAllowed, address)
	}
	return connection, err
}

func ServeClient(ctx context.Context, listenAddress string, session Session) error {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen local SOCKS5: %w", err)
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("SOCKS5 proxy listening on %s", listener.Addr())
	fmt.Fprintf(os.Stderr, "Try `curl --socks5-hostname %s http://%s/`\n", listener.Addr(), HTTPAddress)
	fmt.Fprintf(os.Stderr, "Try `curl --socks5-hostname %s https://github.com/`\n", listener.Addr())
	fmt.Fprintf(os.Stderr, "Blocked by the server example policy: `curl --socks5-hostname %s https://example.com/`\n", listener.Addr())
	fmt.Fprintf(os.Stderr, "Blocked by the server example policy: `curl --socks5-hostname %s http://208.67.220.220/`\n", listener.Addr())
	dialer := routedDialer{
		vpn: session,
		wan: socks5.ProxyDialer{ProxyAddress: EgressSOCKS5Address, Transport: session},
	}
	return socks5.Serve(ctx, listener, dialer, logger)
}

type routedDialer struct {
	vpn socks5.Dialer
	wan socks5.Dialer
}

func (d routedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil && internalNetwork.Contains(ip.Unmap()) {
			return d.vpn.DialContext(ctx, network, address)
		}
	}
	return d.wan.DialContext(ctx, network, address)
}

func Must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
