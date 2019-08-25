// +build !confonly

package dns

import (
	"context"
	goerr "errors"
	"strings"
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
	var lastErr error

	for max > 0 {
		max--
		r, ttls, err := c.resolver.LookupA(ctx, host)
		if isDOHServerError(err) {
			newError("DOH LookupIPv4 serverErr: ", host).Base(err).AtWarning().WriteToLog()
			return nil, err
		}
		if err != nil {
			lastErr = err
			if err == context.Canceled || err == context.DeadlineExceeded {
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
		return nil, lastErr
	}

	ret := &dohIPRecord{
		ips:    resolvedIPs,
		expire: time.Now().Add(time.Duration(int64(ttl)) * time.Second),
	}
	return ret, nil
}

func (c *DOHClient) lookupIPv6(ctx context.Context, host string) (*dohIPRecord, error) {
	var ttl uint32 = 600
	resolvedIPs := make([]net.IP, 0)
	max := 3
	var lastErr error
	for max > 0 {
		max--
		r, ttls, err := c.resolver.LookupAAAA(ctx, host)
		if isDOHServerError(err) {
			newError("DOH LookupIPv6 serverErr: ", host).Base(err).AtWarning().WriteToLog()
			return nil, err
		}
		if err != nil {
			lastErr = err
			if err == context.Canceled || err == context.DeadlineExceeded {
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
		return nil, lastErr
	}

	ret := &dohIPRecord{
		ips:    resolvedIPs,
		expire: time.Now().Add(time.Duration(int64(ttl)) * time.Second),
	}
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
	var lastErr error

	if option.IPv4Enable {
		rec, err := c.lookupIPv4(ctx, domain)
		if err == nil {
			record.A = rec
		}
		lastErr = err
	}

	if option.IPv6Enable {
		rec, err := c.lookupIPv6(ctx, domain)
		if err == nil {
			record.AAAA = rec
		}
		lastErr = err
	}

	if record.A != nil || record.AAAA != nil {
		return record, nil
	}
	if lastErr == nil {
		return nil, dns.ErrEmptyResponse
	}
	return nil, lastErr
}

func (c *DOHClient) dohLookupDual(ctx context.Context, domain string) (*dohDNSResult, error) {
	record := &dohDNSResult{domain: domain}
	var wg sync.WaitGroup
	var errmu sync.Mutex
	lastErr := goerr.New("DOH Lookup")
	wg.Add(2)
	go func() {
		rec, err := c.lookupIPv4(ctx, domain)
		if err == nil {
			record.A = rec
		} else {
			errmu.Lock()
			lastErr = goerr.New(lastErr.Error() + " > " + err.Error())
			errmu.Unlock()
		}
		wg.Done()
	}()

	go func() {
		rec, err := c.lookupIPv6(ctx, domain)
		if err == nil {
			record.AAAA = rec
		} else {
			errmu.Lock()
			lastErr = goerr.New(lastErr.Error() + " > " + err.Error())
			errmu.Unlock()
		}
		wg.Done()
	}()

	wg.Wait()
	if record.A != nil || record.AAAA != nil {
		return record, nil
	}
	return nil, lastErr
}

func (c *DOHClient) QueryIP(ctx context.Context, domain string, option IPOption) ([]net.IP, error) {

	// skip domain without any dot(.)
	if strings.Index(domain, ".") == -1 {
		return nil, newError("invalid domain name")
	}

	if rec, err := c.getCache(domain, option); err == nil {
		return rec, nil
	}

	// cache missed, check if is pending
	c.RLock()
	pp, pok := c.pending[domain]
	c.RUnlock()

	if pok {
		// is pending, wait until cache is ready
		newError("DOH pending wait ", domain).AtWarning().WriteToLog()
		<-pp.done
		if rec, err := c.getCache(domain, option); err == nil {
			return rec, nil
		}
		return nil, dns.ErrEmptyResponse
	}

	// mark the pending request
	c.Lock()
	c.pending[domain] = &dohPendingRequest{
		expire: time.Now().Add(time.Second * 10),
		done:   make(chan struct{}),
	}
	c.Unlock()

	// not in pending, do resolve
	start := time.Now()
	var rec *dohDNSResult
	var lerr error
	if option.IPv4Enable && option.IPv6Enable {
		rec, lerr = c.dohLookupDual(ctx, domain)
	} else {
		rec, lerr = c.dohLookup(ctx, domain, option)
	}
	elapsed := time.Since(start)

	c.Lock()
	if lerr == nil && rec != nil {
		// result ok, set cache
		c.dnsResult[domain] = rec
	}

	// clear pending status
	p := c.pending[domain]
	close(p.done)
	delete(c.pending, domain)
	c.Unlock()

	if rec != nil {
		ips := rec.getIPs(option)
		newError("DOH resolve time ", domain, " ", elapsed, " ", ips).AtWarning().WriteToLog()
		common.Must(c.cleanup.Start())
		return ips, nil
	}

	newError("DOH resolve error ", domain, " ", elapsed, " ", lerr).AtWarning().WriteToLog()
	if lerr == nil {
		return nil, dns.ErrEmptyResponse
	}
	return nil, lerr
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
		} else {
			c.dnsResult[domain] = record
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
func NewDOHClient(address net.Destination, dohHost string, dispatcher routing.Dispatcher, clientIP net.IP) *DOHClient {

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
			Host:       dohHost,
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
