// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

type GeoLocation struct {
	City      string
	Region    string
	Country   string
	Latitude  *float64
	Longitude *float64
}

func GetClientIPAddressesWithoutInternalIPs(ipAddresses []string) (string, error) {
	var res string

	for i := len(ipAddresses) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ipAddresses[i])

		if !net.ParseIP(ip).IsPrivate() {
			res = ip
			break
		}
	}

	return res, nil
}

// TrustedProxies says which peers may tell us the client's address: a header is
// believed only if the TCP peer is inside one of the CIDRs. The zero value trusts
// nobody, so every header is ignored.
type TrustedProxies struct {
	// Header is the one header the edge sets, e.g. True-Client-IP or X-Forwarded-For.
	Header string
	CIDRs  []netip.Prefix
}

// ParseTrustedProxies parses CIDRs (a bare address counts as a single host).
func ParseTrustedProxies(header string, cidrs []string) (TrustedProxies, error) {
	t := TrustedProxies{Header: header}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			a, aerr := netip.ParseAddr(strings.TrimSpace(c))
			if aerr != nil {
				return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q: %w", c, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		u, err := unmapPrefix(p)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q: %w", c, err)
		}
		t.CIDRs = append(t.CIDRs, u)
	}
	return t, nil
}

// unmapPrefix turns an IPv4-mapped prefix (::ffff:10.0.0.0/104) into the IPv4 one,
// as addresses are unmapped before they are compared. A mapped prefix shorter than
// /96 spans more than the IPv4 space and cannot be expressed: an error, as it would
// otherwise silently trust nobody.
func unmapPrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.Addr().Is4In6() {
		return p.Masked(), nil
	}
	if p.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("an IPv4-mapped prefix needs at least 96 bits, got %d", p.Bits())
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), nil
}

func (t TrustedProxies) trusts(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range t.CIDRs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// peer returns the address of the TCP peer, and whether it is a trusted proxy.
func (t TrustedProxies) peer(r *http.Request) (netip.Addr, bool) {
	a, ok := parseAddr(r.RemoteAddr)
	return a, ok && t.trusts(a)
}

// ClientIP is the address of the client: the TCP peer, unless that is a trusted
// proxy, in which case it is taken from the configured header. For X-Forwarded-For
// it is the right-most entry that is not itself a trusted proxy.
func (t TrustedProxies) ClientIP(r *http.Request) string {
	peer, trusted := t.peer(r)
	peerStr := r.RemoteAddr // what we cannot parse is passed on as it is
	if peer.IsValid() {
		peerStr = peer.String()
	}
	if !trusted || t.Header == "" {
		return peerStr
	}
	vals := r.Header.Values(t.Header)
	if http.CanonicalHeaderKey(t.Header) != "X-Forwarded-For" {
		if len(vals) == 1 {
			if a, ok := parseAddr(vals[0]); ok {
				return a.String()
			}
		}
		return peerStr
	}
	var entries []string
	for _, v := range vals {
		entries = append(entries, strings.Split(v, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, ok := parseAddr(entries[i])
		if !ok {
			// Garbage in the chain: nothing to the left of it can be believed.
			break
		}
		if !t.trusts(a) {
			return a.String()
		}
	}
	return peerStr
}

// GeoLocation reads the Cf-* geo headers, but only from a trusted proxy.
func (t TrustedProxies) GeoLocation(r *http.Request) *GeoLocation {
	if _, trusted := t.peer(r); !trusted {
		return &GeoLocation{}
	}
	return &GeoLocation{
		City:      r.Header.Get("Cf-Ipcity"),
		Region:    r.Header.Get("Cf-Region-Code"),
		Country:   r.Header.Get("Cf-Ipcountry"),
		Longitude: parseFloatHeaderValue(r.Header.Get("Cf-Iplongitude")),
		Latitude:  parseFloatHeaderValue(r.Header.Get("Cf-Iplatitude")),
	}
}

type clientInfoKey struct{}

type clientInfo struct {
	ip  string
	geo *GeoLocation
}

// ContextWithClientInfo resolves the client's address and location once, with
// the given trusted proxies, and stores them in the request's context.
func ContextWithClientInfo(r *http.Request, t TrustedProxies) context.Context {
	return context.WithValue(r.Context(), clientInfoKey{}, &clientInfo{ip: t.ClientIP(r), geo: t.GeoLocation(r)})
}

// ClientIP is the client's address as resolved by ContextWithClientInfo. Without
// it, headers are ignored and it is the TCP peer: safe by default.
func ClientIP(r *http.Request) string {
	if ci, ok := r.Context().Value(clientInfoKey{}).(*clientInfo); ok {
		return ci.ip
	}
	return TrustedProxies{}.ClientIP(r)
}

func parseFloatHeaderValue(headerValue string) *float64 {
	if headerValue == "" {
		return nil
	}

	val, err := strconv.ParseFloat(headerValue, 64)
	if err != nil {
		return nil
	}

	return &val
}

// ClientGeoLocation is the client's location as resolved by ContextWithClientInfo;
// empty without it.
func ClientGeoLocation(r *http.Request) *GeoLocation {
	if ci, ok := r.Context().Value(clientInfoKey{}).(*clientInfo); ok {
		return ci.geo
	}
	return &GeoLocation{}
}
