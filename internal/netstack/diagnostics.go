package netstack

// Diagnostics snapshots counters without walking or locking individual sockets.
// Packet and error counters are cumulative for the lifetime of this stack.
func (s *Stack) Diagnostics() map[string]uint64 {
	stats := s.stack.Stats()
	result := map[string]uint64{
		"tcp_connected":   stats.TCP.CurrentConnected.Value(),
		"tcp_established": stats.TCP.CurrentEstablished.Value(),
		"tcp_retransmits": stats.TCP.Retransmits.Value(),
		"tcp_timeouts":    stats.TCP.Timeouts.Value(),
		"tcp_send_errors": stats.TCP.SegmentSendErrors.Value(),
		"udp_buffer_drops": stats.UDP.ReceiveBufferErrors.Value(),
		"link_queue":       uint64(s.link.NumQueued()),
	}
	if device, ok := s.device.(interface{ QueueStats() (int, int, uint64) }); ok {
		outbound, inbound, dropped := device.QueueStats()
		result["tunnel_tx_queue"] = uint64(outbound)
		result["tunnel_rx_queue"] = uint64(inbound)
		result["tunnel_rx_drops"] = dropped
	}
	return result
}
