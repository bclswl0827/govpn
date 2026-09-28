package govpn

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRuleTrafficPolicyHostnameBlacklist(t *testing.T) {
	policy, err := NewRuleTrafficPolicy(TrafficActionAllow, []TrafficRule{{
		Name: "blocked-site", Action: TrafficActionDeny,
		Directions:       []TrafficDirection{TrafficDirectionServerEgress},
		DestinationHosts: []string{"example.com", "*.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		direction TrafficDirection
		host      string
		want      TrafficAction
	}{
		{TrafficDirectionServerEgress, "example.com", TrafficActionDeny},
		{TrafficDirectionServerEgress, "WWW.Example.Com.", TrafficActionDeny},
		{TrafficDirectionServerEgress, "notexample.com", TrafficActionAllow},
		{TrafficDirectionClientIngress, "example.com", TrafficActionAllow},
	}
	for _, test := range tests {
		decision := policy.Decide(TrafficFlow{Direction: test.direction, DestinationHost: test.host})
		if decision.Action != test.want {
			t.Errorf("direction=%s host=%q: action=%s, want %s", test.direction, test.host, decision.Action, test.want)
		}
	}
}

func TestRuleTrafficPolicyCIDRWhitelist(t *testing.T) {
	policy, err := NewRuleTrafficPolicy(TrafficActionDeny, []TrafficRule{{
		Name: "internal-https", Action: TrafficActionAllow,
		DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		IPProtocols:         []uint8{6}, DestinationPorts: []PortRange{{First: 443, Last: 443}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	allowed := TrafficFlow{
		DestinationIP: netip.MustParseAddr("10.20.1.2"), IPProtocol: 6,
		DestinationPort: 443, PortsValid: true,
	}
	if decision := policy.Decide(allowed); !decision.Allowed() || decision.Rule != "internal-https" {
		t.Fatalf("allowed flow decision = %+v", decision)
	}
	allowed.DestinationPort = 80
	if decision := policy.Decide(allowed); decision.Allowed() {
		t.Fatalf("port 80 decision = %+v, want deny", decision)
	}
}

func TestRuleTrafficPolicyFragmentFailsClosed(t *testing.T) {
	policy, err := NewRuleTrafficPolicy(TrafficActionAllow, []TrafficRule{{
		Name: "block-https", Action: TrafficActionDeny, IPProtocols: []uint8{6},
		DestinationPorts: []PortRange{{First: 443, Last: 443}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Decide(TrafficFlow{IPProtocol: 6, Fragmented: true})
	if decision.Allowed() || decision.Rule != "block-https" {
		t.Fatalf("fragment decision = %+v, want port-rule deny", decision)
	}
}

func TestEvaluateTrafficPacketAndCallback(t *testing.T) {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], netip.MustParseAddr("192.0.2.2").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("198.51.100.8").AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 53)

	called := 0
	decision := EvaluateTrafficPacket(
		TrafficPolicyFunc(func(flow TrafficFlow) TrafficDecision {
			if flow.SourceIP.String() != "192.0.2.2" || flow.DestinationIP.String() != "198.51.100.8" ||
				flow.IPProtocol != 17 || !flow.PortsValid || flow.SourcePort != 12345 || flow.DestinationPort != 53 {
				t.Fatalf("unexpected flow: %+v", flow)
			}
			return TrafficDecision{Action: TrafficActionAllow, Rule: "dns"}
		}),
		func(event TrafficPolicyEvent) {
			called++
			if event.Flow.VPNProtocol != ProtocolIKEv2 || event.Decision.Rule != "dns" {
				t.Fatalf("unexpected event: %+v", event)
			}
		},
		ProtocolIKEv2, TrafficDirectionClientIngress, packet,
	)
	if !decision.Allowed() || called != 1 {
		t.Fatalf("decision=%+v callback count=%d", decision, called)
	}
}

func TestEvaluateTrafficInvalidDecisionFailsClosed(t *testing.T) {
	decision := EvaluateTraffic(TrafficPolicyFunc(func(TrafficFlow) TrafficDecision {
		return TrafficDecision{Rule: "invalid"}
	}), nil, TrafficFlow{})
	if decision.Allowed() || decision.Action != TrafficActionDeny {
		t.Fatalf("decision = %+v, want deny", decision)
	}
}
