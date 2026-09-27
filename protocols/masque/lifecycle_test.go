package masque

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestVersionFallbackPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		disabled bool
		failure  error
		want     []int
		success  bool
	}{
		{"unavailable", false, ErrHTTPVersionUnavailable, []int{3, 2}, true},
		{"disabled", true, ErrHTTPVersionUnavailable, []int{3}, false},
		{"HTTP rejection", false, errors.New("HTTP 401"), []int{3}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			var versions []int
			c := Config{Server: "unused", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, DisableVersionFallback: test.disabled,
				Dialer: TunnelDialFunc(func(_ context.Context, d DialRequest) (Tunnel, error) {
					versions = append(versions, d.Version)
					if d.Version == 3 {
						return nil, test.failure
					}
					return local, nil
				}),
			}
			tunnel, _, err := establish(ctx, c)
			if (err == nil) != test.success {
				t.Fatalf("err=%v", err)
			}
			if tunnel != nil {
				tunnel.conn.Close()
			}
			if len(versions) != len(test.want) {
				t.Fatalf("versions=%v", versions)
			}
			for i, v := range versions {
				if v != test.want[i] {
					t.Fatalf("versions=%v", versions)
				}
			}
		})
	}
}
func TestClientReconnectSuspendResumeAndAddressUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened := make(chan net.Conn, 8)
	var mu sync.Mutex
	count := 0
	dialer := TunnelDialFunc(func(ctx context.Context, _ DialRequest) (Tunnel, error) {
		local, remote := net.Pipe()
		mu.Lock()
		count++
		n := count
		mu.Unlock()
		opened <- remote
		go func() {
			reader := bufio.NewReader(remote)
			if _, _, err := readCapsule(reader); err != nil {
				return
			}
			a := netip.AddrFrom4([4]byte{192, 0, 2, byte(n + 1)})
			if err := writeCapsule(remote, capsuleAssign, encodeAddresses([]assignedAddress{{prefix: netip.PrefixFrom(a, 32)}})); err != nil {
				return
			}
			for {
				if _, _, err := readCapsule(reader); err != nil {
					return
				}
			}
		}()
		return local, nil
	})
	client := NewClient(Config{Server: "unused", Dialer: dialer, ReconnectInitial: time.Millisecond, ReconnectMax: 5 * time.Millisecond})
	session, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	first := <-opened
	first.Close()
	var second net.Conn
	select {
	case second = <-opened:
	case <-ctx.Done():
		t.Fatal("did not reconnect")
	}
	defer second.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if got := session.Addresses(); len(got) != 1 || got[0].String() != "192.0.2.3/32" {
		t.Fatalf("new assignment=%v", got)
	}
	client.Suspend()
	if client.Ready() {
		t.Fatal("suspended client reports ready")
	}
	client.Resume()
	var third net.Conn
	select {
	case third = <-opened:
	case <-ctx.Done():
		t.Fatal("did not resume")
	}
	defer third.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	session.Close()
	if client.Ready() {
		t.Fatal("closed client reports ready")
	}
}

func TestExplicitResumeWithAutomaticReconnectDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	opened := make(chan net.Conn, 8)
	client := NewClient(Config{Server: "unused", DisableReconnect: true,
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")},
		Dialer: TunnelDialFunc(func(_ context.Context, _ DialRequest) (Tunnel, error) {
			local, remote := net.Pipe()
			opened <- remote
			return local, nil
		}),
	})
	session, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	first := <-opened
	defer first.Close()
	// Resume before the canceled connection has finished draining.
	client.Suspend()
	client.Resume()
	select {
	case second := <-opened:
		defer second.Close()
	case <-ctx.Done():
		t.Fatal("explicit resume was treated as an automatic reconnect")
	}
	if err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if !client.Configuration().Ready {
		t.Fatal("active configuration is not ready")
	}
}

func TestReconnectBackoffAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	attempts := make(chan time.Time, 8)
	count := 0
	client := NewClient(Config{Server: "unused", DisableVersionFallback: true,
		Addresses:        []netip.Addr{netip.MustParseAddr("192.0.2.2")},
		ReconnectInitial: 10 * time.Millisecond, ReconnectMax: 40 * time.Millisecond,
		Dialer: TunnelDialFunc(func(_ context.Context, _ DialRequest) (Tunnel, error) {
			count++
			if count == 1 {
				return local, nil
			}
			attempts <- time.Now()
			return nil, errors.New("offline")
		}),
	})
	session, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	remote.Close()
	var previous time.Time
	for i := 0; i < 4; i++ {
		select {
		case now := <-attempts:
			minimum := []time.Duration{0, 20 * time.Millisecond, 40 * time.Millisecond, 40 * time.Millisecond}[i]
			if i > 0 && now.Sub(previous) < minimum-time.Millisecond {
				t.Fatalf("retry %d came too early: %s", i, now.Sub(previous))
			}
			previous = now
		case <-ctx.Done():
			t.Fatal("retries stopped")
		}
	}
	session.Close()
	if err := client.WaitReady(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed client readiness error=%v", err)
	}
}
