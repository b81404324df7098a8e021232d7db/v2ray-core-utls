// +build !confonly

package dns

import (
	"context"
	"sync"
	"time"

	"v2ray.com/core/common"
	"v2ray.com/core/common/errors"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/task"
	"v2ray.com/core/features/dns"
	"v2ray.com/core/features/routing"

	"net/http"

	doh "github.com/vcptr/go-doh-client"
)

var (
	dohCacheNotFound = errors.New("DoH Cache Not Found")
	dohCacheExpired  = errors.New("DoH Cache Expired")
)

type dohIPRecord struct {
	ips    []net.IP
	expire time.Time
}

type dohDNSResult struct {
	domain string
	A      *dohIPRecord
	AAAA   *dohIPRecord
}

func (r *dohDNSResult) getIPs(option IPOption) []net.IP {
	resolvedIPs := make([]net.IP, 0)
	now := time.Now()
	if option.IPv6Enable && r.AAAA != nil {
		if r.AAAA.expire.After(now) {
			resolvedIPs = append(resolvedIPs, r.AAAA.ips...)
		} else {
			newError("DOH Cache Expired IPv6 ", r.domain).AtWarning().WriteToLog()
		}
	}

	if option.IPv4Enable && r.A != nil {
		if r.A.expire.After(now) {
			resolvedIPs = append(resolvedIPs, r.A.ips...)
		} else {
			newError("DOH Cache Expired IPv4 ", r.domain).AtWarning().WriteToLog()
		}
	}
	return resolvedIPs
}

type dohPendingRequest struct {
	expire time.Time
	done   chan struct{}
}

// Client is an implementation of dns.Client, which queries localhost for DNS.
type DOHClient struct {
	sync.RWMutex
	resolver doh.Resolver

	dnsResult map[string]*dohDNSResult
	pending   map[string]*dohPendingRequest

	clientIP net.IP
	cleanup  *task.Periodic
}

// Type implements common.HasType.
func (*DOHClient) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (*DOHClient) Start() error { return nil }

// Close implements common.Closable.
func (*DOHClient) Close() error { return nil }

// LookupIPv4 implements IPv4Lookup.
func (c *DOHClient) lookupIPv4(ctx context.Context, host string) (*dohIPRecord, error) {
	var ttl uint32 = 600
	resolvedIPs := make([]net.IP, 0)
	var max = 3
	for max > 0 {
		max--
		r, ttls, err := c.resolver.LookupA(ctx, host)
		if isDOHServerError(err) {
			newError("DOH LookupIPv4 serverErr: ", host).Base(err).AtWarning().WriteToLog()
			return nil, err
		}
		if err != nil {
			if ctx.Err() != nil {
				newError("DOH LookupIPv4 context err: ", host).Base(err).AtWarning().WriteToLog()
				return nil, err
			}
			newError("DOH LookupIPv4 retry: ", host, "  ", max).Base(err).AtWarning().WriteToLog()
			continue
		}
		for idx, ip := range r {
			ip := net.ParseIP(ip.IP4)
			if ip != nil {
				resolvedIPs = append(resolvedIPs, ip)
			}
			if ttls[idx] > ttl {
				ttl = ttls[idx]
			}
		}
		break
	}

	if len(resolvedIPs) == 0 {
		return nil, dns.ErrEmptyResponse
	}

	ret := &dohIPRecord{
		ips:    resolvedIPs,
		expire: time.Now().Add(time.Duration(int64(ttl)) * time.Second),
	}
	newError("DOH lookupIPv4 ", host, " ", ret.ips).AtWarning().WriteToLog()
	return ret, nil
}

func (c *DOHClient) lookupIPv6(ctx context.Context, host string) (*dohIPRecord, error) {
	var ttl uint32 = 600
	resolvedIPs := make([]net.IP, 0)
	max := 3
	for max > 0 {
		max--
		r, ttls, err := c.resolver.LookupAAAA(ctx, host)
		if isDOHServerError(err) {
			newError("DOH LookupIPv6 serverErr: ", host).Base(err).AtWarning().WriteToLog()
			return nil, err
		}
		if err != nil {
			if ctx.Err() != nil {
				newError("DOH LookupIPv6 context err: ", host).Base(err).AtWarning().WriteToLog()
				return nil, err
			}
			newError("DOH LookupIPv6 retry: ", host, " ", max).Base(err).AtWarning().WriteToLog()
			continue
		}
		for idx, ip := range r {
			ip := net.ParseIP(ip.IP6)
			if ip != nil {
				resolvedIPs = append(resolvedIPs, ip)
			}
			if ttls[idx] > ttl {
				ttl = ttls[idx]
			}
		}
		break
	}

	if len(resolvedIPs) == 0 {
		return nil, dns.ErrEmptyResponse
	}

	ret := &dohIPRecord{
		ips:    resolvedIPs,
		expire: time.Now().Add(time.Duration(int64(ttl)) * time.Second),
	}
	newError("DOH lookupIPv6 ", host, " ", ret.ips).AtWarning().WriteToLog()

	return ret, nil
}

func (c *DOHClient) getCache(domain string, option IPOption) ([]net.IP, error) {
	// cached result
	c.RLock()
	defer c.RUnlock()

	rr, cok := c.dnsResult[domain]
	if cok {
		ips := rr.getIPs(option)
		if len(ips) > 0 {
			newError("DOH Cache HIT ", domain, " ", ips).AtWarning().WriteToLog()
			return ips, nil
		}
	}
	return nil, dohCacheNotFound
}

func (c *DOHClient) dohLookup(ctx context.Context, domain string, option IPOption) (*dohDNSResult, error) {

	record := &dohDNSResult{domain: domain}

	if option.IPv4Enable {
		rec, err := c.lookupIPv4(ctx, domain)
		if err == nil {
			record.A = rec
		}
	}

	if option.IPv6Enable {
		rec, err := c.lookupIPv6(ctx, domain)
		if err == nil {
			record.AAAA = rec
		}
	}

	if record.A != nil || record.AAAA != nil {
		return record, nil
	}
	return nil, dns.ErrEmptyResponse
}

func (c *DOHClient) dohLookupDual(ctx context.Context, domain string) (*dohDNSResult, error) {
	record := &dohDNSResult{domain: domain}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		rec, err := c.lookupIPv4(_ctx, domain)
		if err == nil {
			record.A = rec
		}
		wg.Done()
	}()

	go func() {
		_ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		rec, err := c.lookupIPv6(_ctx, domain)
		if err == nil {
			record.AAAA = rec
		}
		wg.Done()
	}()

	wg.Wait()
	if record.A != nil || record.AAAA != nil {
		return record, nil
	}
	return nil, dns.ErrEmptyResponse
}

func (c *DOHClient) QueryIP(ctx context.Context, domain string, option IPOption) ([]net.IP, error) {

	if rec, err := c.getCache(domain, option); err == nil {
		return rec, nil
	}

	// cache missed, check if is pending
	c.RLock()
	pp, pok := c.pending[domain]
	c.RUnlock()

	if !pok {
		// not in pending, do resolve
		c.Lock()

		// mark the pending request
		c.pending[domain] = &dohPendingRequest{
			expire: time.Now().Add(time.Second * 10),
			done:   make(chan struct{}),
		}
		c.Unlock()

		start := time.Now()
		// do resolve
		var rec *dohDNSResult
		var err error
		if option.IPv4Enable && option.IPv6Enable {
			rec, err = c.dohLookupDual(ctx, domain)
		} else {
			rec, err = c.dohLookup(ctx, domain, option)
		}
		elapsed := time.Since(start)
		newError("DOH resolve time ", domain, " ", elapsed).AtWarning().WriteToLog()

		c.Lock()
		if err == nil && rec != nil {
			// result ok, set cache
			c.dnsResult[domain] = rec
		}

		// clear pending status
		p := c.pending[domain]
		close(p.done)
		delete(c.pending, domain)
		c.Unlock()

		if rec != nil {
			common.Must(c.cleanup.Start())
			return rec.getIPs(option), nil
		}

		return nil, dns.ErrEmptyResponse
	}

	// pending, wait until cache is ready
	newError("DOH pending wait ", domain).AtWarning().WriteToLog()
	<-pp.done
	if rec, err := c.getCache(domain, option); err == nil {
		return rec, nil
	}
	return nil, dns.ErrEmptyResponse
}

func (c *DOHClient) Cleanup() error {
	now := time.Now()
	c.Lock()
	defer c.Unlock()

	if len(c.dnsResult) == 0 && len(c.pending) == 0 {
		return newError("DOH Cleanup: nothing to do. stopping...")
	}

	for domain, record := range c.dnsResult {
		if record.A != nil && record.A.expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.expire.Before(now) {
			record.A = nil
		}
		if record.A == nil && record.AAAA == nil {
			delete(c.dnsResult, domain)
			newError("DOH cache expired cleaned up ", domain).AtWarning().WriteToLog()
		}
	}

	if len(c.dnsResult) == 0 {
		c.dnsResult = make(map[string]*dohDNSResult)
	}

	for domain, req := range c.pending {
		if req.expire.Before(now) {
			delete(c.pending, domain)
		}
	}

	if len(c.pending) == 0 {
		c.pending = make(map[string]*dohPendingRequest)
	}

	return nil
}

func (c *DOHClient) Name() string {
	return "dohdns"
}

// New create a new dns.Client
func NewDOHClient(address net.Destination, dispatcher routing.Dispatcher, clientIP net.IP) *DOHClient {

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		r, err := dispatcher.Dispatch(ctx, address)
		if err != nil {
			return nil, err
		}
		return net.NewConnection(
			net.ConnectionInputMulti(r.Writer),
			net.ConnectionOutputMulti(r.Reader),
		), nil
	}

	tr := &http.Transport{
		DialContext:         dial,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   16 * time.Second,
	}

	c := &DOHClient{
		resolver: doh.Resolver{
			Host:       address.NetAddr(),
			Class:      doh.IN,
			HTTPClient: httpClient,
		},
		dnsResult: make(map[string]*dohDNSResult),
		pending:   make(map[string]*dohPendingRequest),
	}
	c.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  c.Cleanup,
	}
	return c
}

func isDOHServerError(err error) bool {
	switch err {
	case doh.ErrFormatError, doh.ErrServerFailure, doh.ErrNameError, doh.ErrNotImplemented, doh.ErrRefused:
		return true
	}
	return false
}
