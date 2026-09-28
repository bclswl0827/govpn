package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/bclswl0827/govpn"
)

type Client struct {
	Config    Config
	runtimeMu sync.RWMutex
	runtime   *Runtime
}

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	if len(c.Config.Address) == 0 {
		return nil, errors.New("wireguard: at least one address is required")
	}
	peers, err := preparePeers(ctx, c.Config.Peers)
	if err != nil {
		return nil, err
	}
	addresses, err := parseAddresses(c.Config.Address)
	if err != nil {
		return nil, err
	}
	mtu := normalizedMTU(c.Config.MTU)
	if mtu == 0 {
		return nil, fmt.Errorf("wireguard: invalid MTU %d", c.Config.MTU)
	}
	if err := validateAddressMTU(addresses, mtu); err != nil {
		return nil, err
	}
	uapi, err := buildUAPIWithMark(c.Config.PrivateKey, c.Config.ListenPort, c.Config.FirewallMark, peers)
	if err != nil {
		return nil, err
	}
	session, runtime, err := start(addresses, mtu, uapi, peers, c.Config.Logger, nil)
	if err != nil {
		return nil, err
	}
	c.runtimeMu.Lock()
	c.runtime = runtime
	c.runtimeMu.Unlock()
	return session, nil
}

func (c *Client) Runtime() (*Runtime, error) {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	if c.runtime == nil {
		return nil, ErrNotStarted
	}
	return c.runtime, nil
}

func (c *Client) Status() (Status, error) {
	runtime, err := c.Runtime()
	if err != nil {
		return Status{}, err
	}
	return runtime.Status()
}

func (c *Client) UAPIGet() (string, error) {
	runtime, err := c.Runtime()
	if err != nil {
		return "", err
	}
	return runtime.UAPIGet()
}

func (c *Client) UAPISet(configuration string) error {
	runtime, err := c.Runtime()
	if err != nil {
		return err
	}
	return runtime.UAPISet(configuration)
}
