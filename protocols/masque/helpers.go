package masque

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func options(path string, mtu int) (string, int, error) {
	if path == "" {
		path = DefaultPath
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
		u.Host != "" || u.Fragment != "" || strings.ContainsAny(path, "{}\r\n") {
		return "", 0, errors.New("masque: path must be an expanded absolute request path")
	}
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu < 1280 || mtu > 65535 {
		return "", 0, errors.New("masque: MTU must be between 1280 and 65535")
	}
	return path, mtu, nil
}

func upgradeHeader(h http.Header) bool {
	if !strings.EqualFold(h.Get("Upgrade"), "connect-ip") || h.Get("Capsule-Protocol") != "?1" {
		return false
	}
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func connectProtocol(request *http.Request) string {
	if request.Proto == "" {
		return "connect-ip"
	}
	return request.Proto
}
