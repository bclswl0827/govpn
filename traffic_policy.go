package govpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// TrafficDirection identifies traffic relative to a VPN server.
type TrafficDirection uint8

const (
	TrafficDirectionUnspecified TrafficDirection = iota
	// TrafficDirectionClientIngress is an IP packet received from an
	// authenticated VPN client.
	TrafficDirectionClientIngress
	// TrafficDirectionServerEgress is a connection made by the server on behalf
	// of a VPN client, for example by an application-level proxy.
	TrafficDirectionServerEgress
)

func (d TrafficDirection) String() string {
	switch d {
	case TrafficDirectionClientIngress:
		return "client-ingress"
	case TrafficDirectionServerEgress:
		return "server-egress"
	default:
		return "unspecified"
	}
}

// TrafficAction is the result of a traffic policy decision.
type TrafficAction uint8

const (
	TrafficActionUnspecified TrafficAction = iota
	TrafficActionAllow
	TrafficActionDeny
)

func (a TrafficAction) String() string {
	switch a {
	case TrafficActionAllow:
		return "allow"
	case TrafficActionDeny:
		return "deny"
	default:
		return "unspecified"
	}
}

// TrafficFlow describes one IP flow evaluated by a VPN server. PortsValid is
// false for protocols without ports and for non-initial IP fragments.
type TrafficFlow struct {
	VPNProtocol     Protocol
	Direction       TrafficDirection
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	DestinationHost string
	IPProtocol      uint8
	SourcePort      uint16
	DestinationPort uint16
	PortsValid      bool
	Fragmented      bool
	PacketLength    int
}

// TrafficDecision is returned by TrafficPolicy. Rule and Reason are optional
// audit fields. An unspecified or unknown action is treated as deny.
type TrafficDecision struct {
	Action TrafficAction
	Rule   string
	Reason string
}

// Allowed reports whether the decision explicitly permits the flow.
func (d TrafficDecision) Allowed() bool { return d.Action == TrafficActionAllow }

// TrafficPolicy decides whether an authenticated client's flow may proceed.
// Implementations may be called concurrently and must not retain mutable state
// from TrafficFlow without their own synchronization.
type TrafficPolicy interface {
	Decide(TrafficFlow) TrafficDecision
}

// TrafficPolicyFunc adapts a function to TrafficPolicy.
type TrafficPolicyFunc func(TrafficFlow) TrafficDecision

func (f TrafficPolicyFunc) Decide(flow TrafficFlow) TrafficDecision { return f(flow) }

// TrafficPolicyEvent is delivered after a policy decision has been normalized.
type TrafficPolicyEvent struct {
	Flow     TrafficFlow
	Decision TrafficDecision
}

// TrafficPolicyCallback receives policy decisions synchronously on the packet
// or connection path. It must return promptly and must be safe for concurrent
// use. The callback can record logs, audit events, or metrics.
type TrafficPolicyCallback func(TrafficPolicyEvent)

// PortRange is an inclusive transport-port range.
type PortRange struct {
	First uint16
	Last  uint16
}

// TrafficRule matches a flow when every non-empty selector matches. Entries
// within one selector are alternatives. Rules are evaluated in slice order.
type TrafficRule struct {
	Name                string
	Action              TrafficAction
	Directions          []TrafficDirection
	SourcePrefixes      []netip.Prefix
	DestinationPrefixes []netip.Prefix
	// DestinationHosts contains exact names or leading-wildcard names such as
	// "*.example.com". It only matches application egress that supplies a host.
	DestinationHosts []string
	IPProtocols      []uint8
	SourcePorts      []PortRange
	DestinationPorts []PortRange
}

// RuleTrafficPolicy is an immutable ordered allow/deny policy. Use
// NewRuleTrafficPolicy to validate and copy its rules.
type RuleTrafficPolicy struct {
	defaultAction TrafficAction
	rules         []TrafficRule
}

// NewRuleTrafficPolicy constructs an ordered policy. A default deny action
// with allow rules is a whitelist; a default allow action with deny rules is a
// blacklist. The first matching rule wins.
func NewRuleTrafficPolicy(defaultAction TrafficAction, rules []TrafficRule) (*RuleTrafficPolicy, error) {
	if defaultAction != TrafficActionAllow && defaultAction != TrafficActionDeny {
		return nil, errors.New("govpn: traffic policy default action must be allow or deny")
	}
	cloned := make([]TrafficRule, len(rules))
	for i, rule := range rules {
		if rule.Action != TrafficActionAllow && rule.Action != TrafficActionDeny {
			return nil, fmt.Errorf("govpn: traffic policy rule %d action must be allow or deny", i)
		}
		cloned[i] = cloneTrafficRule(rule)
		for _, direction := range rule.Directions {
			if direction != TrafficDirectionClientIngress && direction != TrafficDirectionServerEgress {
				return nil, fmt.Errorf("govpn: traffic policy rule %d has invalid direction %d", i, direction)
			}
		}
		for _, prefix := range append(append([]netip.Prefix(nil), rule.SourcePrefixes...), rule.DestinationPrefixes...) {
			if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("govpn: traffic policy rule %d has invalid prefix %q", i, prefix)
			}
		}
		for _, host := range rule.DestinationHosts {
			if !validHostPattern(host) {
				return nil, fmt.Errorf("govpn: traffic policy rule %d has invalid destination host %q", i, host)
			}
		}
		for _, ports := range append(append([]PortRange(nil), rule.SourcePorts...), rule.DestinationPorts...) {
			if ports.First > ports.Last {
				return nil, fmt.Errorf("govpn: traffic policy rule %d has descending port range %d-%d", i, ports.First, ports.Last)
			}
		}
	}
	return &RuleTrafficPolicy{defaultAction: defaultAction, rules: cloned}, nil
}

func cloneTrafficRule(rule TrafficRule) TrafficRule {
	rule.Directions = append([]TrafficDirection(nil), rule.Directions...)
	rule.SourcePrefixes = append([]netip.Prefix(nil), rule.SourcePrefixes...)
	rule.DestinationPrefixes = append([]netip.Prefix(nil), rule.DestinationPrefixes...)
	rule.DestinationHosts = append([]string(nil), rule.DestinationHosts...)
	rule.IPProtocols = append([]uint8(nil), rule.IPProtocols...)
	rule.SourcePorts = append([]PortRange(nil), rule.SourcePorts...)
	rule.DestinationPorts = append([]PortRange(nil), rule.DestinationPorts...)
	return rule
}

// Decide implements TrafficPolicy.
func (p *RuleTrafficPolicy) Decide(flow TrafficFlow) TrafficDecision {
	if p == nil {
		return TrafficDecision{Action: TrafficActionDeny, Reason: "nil rule policy"}
	}
	for _, rule := range p.rules {
		if trafficRuleMatches(rule, flow) {
			return TrafficDecision{Action: rule.Action, Rule: rule.Name, Reason: "matched rule"}
		}
		// Without reassembly, a non-initial fragment has no transport ports. A
		// matching port-based deny rule must fail closed or a blacklist could be
		// bypassed by fragmentation.
		if flow.Fragmented && !flow.PortsValid && rule.Action == TrafficActionDeny &&
			(len(rule.SourcePorts) > 0 || len(rule.DestinationPorts) > 0) && trafficRuleBaseMatches(rule, flow) {
			return TrafficDecision{Action: TrafficActionDeny, Rule: rule.Name, Reason: "fragment matched port-based deny rule"}
		}
	}
	return TrafficDecision{Action: p.defaultAction, Reason: "default action"}
}

func trafficRuleMatches(rule TrafficRule, flow TrafficFlow) bool {
	if !trafficRuleBaseMatches(rule, flow) {
		return false
	}
	if len(rule.SourcePorts) > 0 || len(rule.DestinationPorts) > 0 {
		if !flow.PortsValid {
			return false
		}
		if !matchesPort(rule.SourcePorts, flow.SourcePort) || !matchesPort(rule.DestinationPorts, flow.DestinationPort) {
			return false
		}
	}
	return true
}

func trafficRuleBaseMatches(rule TrafficRule, flow TrafficFlow) bool {
	return matchesDirection(rule.Directions, flow.Direction) &&
		matchesPrefixes(rule.SourcePrefixes, flow.SourceIP) &&
		matchesPrefixes(rule.DestinationPrefixes, flow.DestinationIP) &&
		matchesHost(rule.DestinationHosts, flow.DestinationHost) &&
		matchesProtocol(rule.IPProtocols, flow.IPProtocol)
}

func validHostPattern(pattern string) bool {
	pattern = canonicalHost(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "*") {
		return strings.HasPrefix(pattern, "*.") && !strings.Contains(pattern[2:], "*") && len(pattern) > 2
	}
	return true
}

func matchesHost(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	host = canonicalHost(host)
	if host == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = canonicalHost(pattern)
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func canonicalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func matchesDirection(values []TrafficDirection, candidate TrafficDirection) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func matchesPrefixes(prefixes []netip.Prefix, address netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	if !address.IsValid() {
		return false
	}
	address = address.Unmap().WithZone("")
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func matchesProtocol(protocols []uint8, candidate uint8) bool {
	if len(protocols) == 0 {
		return true
	}
	for _, protocol := range protocols {
		if protocol == candidate {
			return true
		}
	}
	return false
}

func matchesPort(ranges []PortRange, candidate uint16) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, ports := range ranges {
		if candidate >= ports.First && candidate <= ports.Last {
			return true
		}
	}
	return false
}

// EvaluateTraffic evaluates and reports one flow. A nil policy permits the
// flow for backward compatibility. Invalid policy results fail closed.
func EvaluateTraffic(policy TrafficPolicy, callback TrafficPolicyCallback, flow TrafficFlow) TrafficDecision {
	if flow.SourceIP.IsValid() {
		flow.SourceIP = flow.SourceIP.Unmap().WithZone("")
	}
	if flow.DestinationIP.IsValid() {
		flow.DestinationIP = flow.DestinationIP.Unmap().WithZone("")
	}
	decision := TrafficDecision{Action: TrafficActionAllow, Reason: "no policy configured"}
	if policy != nil {
		decision = policy.Decide(flow)
		if decision.Action != TrafficActionAllow && decision.Action != TrafficActionDeny {
			decision = TrafficDecision{Action: TrafficActionDeny, Rule: decision.Rule, Reason: "invalid policy decision"}
		}
	}
	if callback != nil {
		callback(TrafficPolicyEvent{Flow: flow, Decision: decision})
	}
	return decision
}

// EvaluateTrafficPacket parses, evaluates, and reports one raw IPv4 or IPv6
// packet. Malformed packets are denied before a custom policy is called.
func EvaluateTrafficPacket(policy TrafficPolicy, callback TrafficPolicyCallback, vpnProtocol Protocol, direction TrafficDirection, packet []byte) TrafficDecision {
	flow, err := parseTrafficPacket(vpnProtocol, direction, packet)
	if err != nil {
		decision := TrafficDecision{Action: TrafficActionDeny, Reason: err.Error()}
		if callback != nil {
			callback(TrafficPolicyEvent{Flow: flow, Decision: decision})
		}
		return decision
	}
	return EvaluateTraffic(policy, callback, flow)
}

func parseTrafficPacket(vpnProtocol Protocol, direction TrafficDirection, packet []byte) (TrafficFlow, error) {
	flow := TrafficFlow{VPNProtocol: vpnProtocol, Direction: direction, PacketLength: len(packet)}
	if len(packet) == 0 {
		return flow, errors.New("invalid empty IP packet")
	}
	var transportOffset int
	var nonInitialFragment bool
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return flow, errors.New("invalid truncated IPv4 packet")
		}
		headerLength := int(packet[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLength < 20 || headerLength > len(packet) || totalLength < headerLength || totalLength > len(packet) {
			return flow, errors.New("invalid IPv4 packet length")
		}
		flow.SourceIP = netip.AddrFrom4([4]byte(packet[12:16]))
		flow.DestinationIP = netip.AddrFrom4([4]byte(packet[16:20]))
		flow.IPProtocol = packet[9]
		transportOffset = headerLength
		fragmentField := binary.BigEndian.Uint16(packet[6:8])
		flow.Fragmented = fragmentField&0x3fff != 0
		nonInitialFragment = fragmentField&0x1fff != 0
		packet = packet[:totalLength]
	case 6:
		if len(packet) < 40 {
			return flow, errors.New("invalid truncated IPv6 packet")
		}
		payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
		if 40+payloadLength > len(packet) {
			return flow, errors.New("invalid IPv6 packet length")
		}
		var source, destination [16]byte
		copy(source[:], packet[8:24])
		copy(destination[:], packet[24:40])
		flow.SourceIP = netip.AddrFrom16(source)
		flow.DestinationIP = netip.AddrFrom16(destination)
		packet = packet[:40+payloadLength]
		flow.IPProtocol, transportOffset, flow.Fragmented, nonInitialFragment = ipv6Transport(packet)
		if transportOffset < 0 {
			return flow, errors.New("invalid IPv6 extension headers")
		}
	default:
		return flow, errors.New("invalid IP version")
	}
	if !nonInitialFragment && hasTransportPorts(flow.IPProtocol) {
		if transportOffset+4 > len(packet) {
			return flow, errors.New("invalid truncated transport header")
		}
		flow.SourcePort = binary.BigEndian.Uint16(packet[transportOffset : transportOffset+2])
		flow.DestinationPort = binary.BigEndian.Uint16(packet[transportOffset+2 : transportOffset+4])
		flow.PortsValid = true
	}
	return flow, nil
}

func ipv6Transport(packet []byte) (protocol uint8, offset int, fragmented, nonInitialFragment bool) {
	protocol, offset = packet[6], 40
	for steps := 0; steps < 16; steps++ {
		switch protocol {
		case 0, 43, 60:
			if offset+2 > len(packet) {
				return 0, -1, fragmented, false
			}
			size := (int(packet[offset+1]) + 1) * 8
			if offset+size > len(packet) {
				return 0, -1, fragmented, false
			}
			protocol, offset = packet[offset], offset+size
		case 44:
			if offset+8 > len(packet) {
				return 0, -1, fragmented, false
			}
			fragmented = true
			nonInitialFragment = binary.BigEndian.Uint16(packet[offset+2:offset+4])>>3 != 0
			protocol, offset = packet[offset], offset+8
		case 51:
			if offset+2 > len(packet) {
				return 0, -1, fragmented, false
			}
			size := (int(packet[offset+1]) + 2) * 4
			if offset+size > len(packet) {
				return 0, -1, fragmented, false
			}
			protocol, offset = packet[offset], offset+size
		default:
			return protocol, offset, fragmented, nonInitialFragment
		}
	}
	return 0, -1, fragmented, false
}

func hasTransportPorts(protocol uint8) bool {
	switch protocol {
	case 6, 17, 33, 132: // TCP, UDP, DCCP, SCTP.
		return true
	default:
		return false
	}
}
