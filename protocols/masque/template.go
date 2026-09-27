package masque

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DefaultTemplate is the RFC 9484 unrestricted CONNECT-IP URI template.
const DefaultTemplate = "/.well-known/masque/ip/{target}/{ipproto}/"

type resourceTemplate struct {
	path   *regexp.Regexp
	names  []string
	query  map[string]string
	source string
}
type requestScope struct {
	target   string
	protocol uint8
}

func parseTemplate(value string) (*resourceTemplate, error) {
	if value == "" || value == DefaultPath {
		value = DefaultTemplate
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "#\r\n ") {
		return nil, errors.New("masque: invalid URI template")
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return nil, errors.New("masque: invalid URI template character")
		}
	}
	// Expand the supported RFC 6570 query operators into named placeholders.
	source := value
	for {
		start := strings.Index(value, "{?")
		amp := strings.Index(value, "{&")
		if start < 0 || amp >= 0 && amp < start {
			start = amp
		}
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start:], '}')
		if end < 0 {
			return nil, errors.New("masque: unterminated URI template")
		}
		end += start
		body := value[start+1 : end]
		var replacement strings.Builder
		for i, name := range strings.Split(body[1:], ",") {
			if name != "target" && name != "ipproto" {
				return nil, errors.New("masque: unsupported template variable")
			}
			if i == 0 {
				replacement.WriteByte(body[0])
			} else {
				replacement.WriteByte('&')
			}
			replacement.WriteString(name + "={" + name + "}")
		}
		value = value[:start] + replacement.String() + value[end+1:]
	}
	path, query, _ := strings.Cut(value, "?")
	t := &resourceTemplate{query: make(map[string]string), source: source}
	pattern := "^"
	for {
		before, after, found := strings.Cut(path, "{")
		pattern += regexp.QuoteMeta(before)
		if !found {
			if strings.Contains(before, "}") {
				return nil, errors.New("masque: unmatched template brace")
			}
			break
		}
		name, rest, ok := strings.Cut(after, "}")
		if !ok || name != "target" && name != "ipproto" {
			return nil, errors.New("masque: unsupported template expression")
		}
		t.names = append(t.names, name)
		pattern += "([^/]*)"
		path = rest
	}
	t.path = regexp.MustCompile(pattern + "$")
	if query != "" {
		for _, part := range strings.Split(query, "&") {
			key, v, ok := strings.Cut(part, "=")
			if !ok {
				return nil, errors.New("masque: query template requires key=value")
			}
			if key == "" || strings.ContainsAny(key, "{}") {
				return nil, errors.New("masque: invalid query template key")
			}
			if strings.ContainsAny(v, "{}") && v != "{target}" && v != "{ipproto}" {
				return nil, errors.New("masque: unsupported query template")
			}
			key, err := url.QueryUnescape(key)
			if err != nil {
				return nil, err
			}
			if _, exists := t.query[key]; exists {
				return nil, errors.New("masque: duplicate query template key")
			}
			if v != "{target}" && v != "{ipproto}" {
				v, err = url.QueryUnescape(v)
				if err != nil {
					return nil, err
				}
			}
			t.query[key] = v
		}
	}
	return t, nil
}
func (t *resourceTemplate) expand(target string, protocol uint8) string {
	if target == "" {
		target = "*"
	}
	proto := "*"
	if protocol != 0 {
		proto = strconv.Itoa(int(protocol))
	}
	value := t.source
	for _, op := range []string{"?", "&"} {
		for {
			i := strings.Index(value, "{"+op)
			if i < 0 {
				break
			}
			j := strings.IndexByte(value[i:], '}') + i
			var pairs []string
			for _, name := range strings.Split(value[i+2:j], ",") {
				v := target
				if name == "ipproto" {
					v = proto
				}
				if v != "*" {
					v = url.QueryEscape(v)
				}
				pairs = append(pairs, name+"="+v)
			}
			value = value[:i] + op + strings.Join(pairs, "&") + value[j+1:]
		}
	}
	escaped := target
	if target != "*" {
		escaped = url.PathEscape(target)
	}
	value = strings.ReplaceAll(value, "{target}", escaped)
	return strings.ReplaceAll(value, "{ipproto}", proto)
}
func (t *resourceTemplate) match(u *url.URL) (requestScope, bool, error) {
	scope := requestScope{target: "*"}
	match := t.path.FindStringSubmatch(u.EscapedPath())
	if match == nil {
		return scope, false, nil
	}
	values := map[string]string{"target": "*", "ipproto": "*"}
	for i, name := range t.names {
		v, err := url.PathUnescape(match[i+1])
		if err != nil {
			return scope, true, err
		}
		values[name] = v
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return scope, true, err
	}
	for key, pattern := range t.query {
		if len(query[key]) > 1 {
			return scope, true, errors.New("masque: duplicate scope query parameter")
		}
		v := query.Get(key)
		if pattern == "{target}" || pattern == "{ipproto}" {
			if query.Has(key) {
				values[strings.Trim(pattern, "{}")] = v
			}
		} else if v != pattern {
			return scope, false, nil
		}
	}
	scope.target = values["target"]
	if scope.target == "" {
		return scope, true, errors.New("masque: empty target")
	}
	if values["ipproto"] != "*" {
		n, err := strconv.ParseUint(values["ipproto"], 10, 8)
		if err != nil {
			return scope, true, errors.New("masque: invalid ipproto")
		}
		scope.protocol = uint8(n)
	}
	return scope, true, nil
}
func targetPrefix(target string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(target); err == nil && a.Zone() == "" && !a.Is4In6() {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(target)
	if err != nil || p != p.Masked() || p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("masque: invalid target prefix")
	}
	return p, nil
}
