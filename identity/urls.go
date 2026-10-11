package identity

import (
	"net"
	"net/url"
)

func localhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func secureURL(u *url.URL) bool {
	return u != nil && u.Host != "" && u.User == nil && u.Fragment == "" &&
		(u.Scheme == "https" || u.Scheme == "http" && localhost(u.Hostname()))
}
