package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	version        = 5
	noAuth         = 0
	noAcceptable   = 0xff
	connectCommand = 1
	succeeded      = 0
	generalError   = 1
	notAllowed     = 2
	commandError   = 7
	addressError   = 8
	addressIPv4    = 1
	addressDomain  = 3
	addressIPv6    = 4
)

func negotiate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != version || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	selected := byte(noAcceptable)
	for _, method := range methods {
		if method == noAuth {
			selected = noAuth
			break
		}
	}
	if _, err := conn.Write([]byte{version, selected}); err != nil {
		return err
	}
	if selected == noAcceptable {
		return errors.New("SOCKS5 client does not support no-authentication mode")
	}
	return nil
}

func readRequest(conn net.Conn) (byte, string, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", "", err
	}
	if header[0] != version || header[2] != 0 {
		return 0, "", "", errors.New("invalid SOCKS5 request")
	}
	var host string
	network := "tcp4"
	switch header[3] {
	case addressIPv4:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return 0, "", "", err
		}
		host = net.IP(address).String()
	case addressIPv6:
		network = "tcp6"
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return 0, "", "", err
		}
		host = net.IP(address).String()
	case addressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return 0, "", "", err
		}
		if length[0] == 0 {
			return 0, "", "", errors.New("empty SOCKS5 domain")
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return 0, "", "", err
		}
		host = string(name)
	default:
		return 0, "", "", errors.New("unsupported SOCKS5 address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return 0, "", "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return header[1], network, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func writeReply(conn net.Conn, status byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		ip, port = tcpAddress.IP, tcpAddress.Port
	}
	if ip4 := ip.To4(); ip4 != nil {
		reply := []byte{version, status, 0, addressIPv4}
		reply = append(reply, ip4...)
		reply = binary.BigEndian.AppendUint16(reply, uint16(port))
		_, err := conn.Write(reply)
		return err
	}
	reply := []byte{version, status, 0, addressIPv6}
	reply = append(reply, ip.To16()...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(port))
	_, err := conn.Write(reply)
	return err
}
