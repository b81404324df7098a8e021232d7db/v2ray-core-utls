// +build !confonly

package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"v2ray.com/core/common"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol/dns"
	"v2ray.com/core/common/session"
	"v2ray.com/core/common/signal/pubsub"
	"v2ray.com/core/common/task"
	dns_feature "v2ray.com/core/features/dns"
	"v2ray.com/core/features/routing"
)

// DoHNameServer implimented DNS over HTTPS (RFC8484) Wire Format,
// which is compatiable with traditional dns over udp(RFC1035),
// thus most of the DOH implimentation is copied from udpns.go
type DoHNameServer struct {
	sync.RWMutex
	ips         map[string]record
	requests    map[uint16]pendingRequest
	pendingWait map[string]struct{}
	pub         *pubsub.Service
	cleanup     *task.Periodic
	reqID       uint32
	clientIP    net.IP
	httpClient  *http.Client
	dohURL      string
	dohHost     string
	name        string
}

func NewDoHNameServer(address net.Destination, dohHost string, dispatcher routing.Dispatcher, clientIP net.IP) *DoHNameServer {

	// Dispatched connection will be closed (interupted) after each request
	// This makes DOH inefficient without a keeped-alive connection
	// See: core/app/proxyman/outbound/handler.go:113
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
	s := &DoHNameServer{
		httpClient:  httpClient,
		ips:         make(map[string]record),
		pendingWait: make(map[string]struct{}),
		requests:    make(map[uint16]pendingRequest),
		clientIP:    clientIP,
		pub:         pubsub.NewService(),
		name:        "DOH:" + dohHost,
		dohHost:     dohHost,
		dohURL:      fmt.Sprintf("https://%s/dns-query", dohHost),
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	return s
}

func NewDoHLocalNameServer(dohHost string, clientIP net.IP) *DoHNameServer {

	s := &DoHNameServer{
		httpClient:  http.DefaultClient,
		ips:         make(map[string]record),
		pendingWait: make(map[string]struct{}),
		requests:    make(map[uint16]pendingRequest),
		clientIP:    clientIP,
		pub:         pubsub.NewService(),
		name:        "DOHL:" + dohHost,
		dohHost:     dohHost,
		dohURL:      fmt.Sprintf("https://%s/dns-query", dohHost),
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	return s
}

func (s *DoHNameServer) Name() string {
	return s.name
}

func (s *DoHNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 && len(s.requests) == 0 {
		return newError("nothing to do. stopping...")
	}

	for domain, record := range s.ips {
		if record.A != nil && record.A.Expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.Expire.Before(now) {
			record.AAAA = nil
		}

		if record.A == nil && record.AAAA == nil {
			newError(s.name, " cleanup ", domain).AtWarning().WriteToLog()
			delete(s.ips, domain)
		} else {
			s.ips[domain] = record
		}
	}

	if len(s.ips) == 0 {
		s.ips = make(map[string]record)
	}

	for id, req := range s.requests {
		if req.expire.Before(now) {
			delete(s.requests, id)
		}
	}

	if len(s.requests) == 0 {
		s.requests = make(map[uint16]pendingRequest)
	}

	if len(s.pendingWait) == 0 {
		s.pendingWait = make(map[string]struct{})
	}

	return nil
}

func (s *DoHNameServer) HandleResponse(payload []byte) {

	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		newError("failed to parse DNS response").Base(err).AtWarning().WriteToLog()
		return
	}
	if err := parser.SkipAllQuestions(); err != nil {
		newError("failed to skip questions in DNS response").Base(err).AtWarning().WriteToLog()
		return
	}

	id := header.ID
	s.Lock()
	req, f := s.requests[id]
	var elapsed time.Duration
	if f {
		elapsed = time.Since(req.expire.Add(time.Second * -8)) // expire is the started time plus 8 secs
		delete(s.requests, id)
	}
	if _, isPending := s.pendingWait[req.domain]; isPending {
		delete(s.pendingWait, req.domain)
	}
	s.Unlock()

	if !f {
		// should never happeded
		return
	}

	domain := req.domain
	recType := req.recType

	now := time.Now()
	var ipRecExpire time.Time
	if header.RCode != dnsmessage.RCodeSuccess {
		ipRecExpire = now.Add(time.Second * 120)
	}

	ipRecord := &IPRecord{
		RCode:  header.RCode,
		Expire: ipRecExpire,
	}

L:
	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			if err != dnsmessage.ErrSectionDone {
				newError("failed to parse answer section for domain: ", domain).Base(err).WriteToLog()
			}
			break
		}
		ttl := header.TTL
		if ttl < 600 {
			ttl = 600
		}
		expire := now.Add(time.Duration(ttl) * time.Second)
		ipRecord.Expire = expire

		if header.Type != recType {
			if err := parser.SkipAnswer(); err != nil {
				newError("failed to skip answer").Base(err).WriteToLog()
				break L
			}
			continue
		}

		switch header.Type {
		case dnsmessage.TypeA:
			ans, err := parser.AResource()
			if err != nil {
				newError("failed to parse A record for domain: ", domain).Base(err).WriteToLog()
				break L
			}
			ipRecord.IP = append(ipRecord.IP, net.IPAddress(ans.A[:]))
		case dnsmessage.TypeAAAA:
			ans, err := parser.AAAAResource()
			if err != nil {
				newError("failed to parse A record for domain: ", domain).Base(err).WriteToLog()
				break L
			}
			ipRecord.IP = append(ipRecord.IP, net.IPAddress(ans.AAAA[:]))
		default:
			if err := parser.SkipAnswer(); err != nil {
				newError("failed to skip answer").Base(err).WriteToLog()
				break L
			}
		}
	}

	var rec record
	switch recType {
	case dnsmessage.TypeA:
		rec.A = ipRecord
	case dnsmessage.TypeAAAA:
		rec.AAAA = ipRecord
	}

	newError(s.name, " updating domain:", domain, " -> ", ipRecord.IP, " ", elapsed).AtWarning().WriteToLog()
	s.updateIP(domain, rec)
}

func (s *DoHNameServer) updateIP(domain string, newRec record) {
	s.Lock()

	rec := s.ips[domain]

	if isNewer(rec.A, newRec.A) {
		rec.A = newRec.A
	}
	if isNewer(rec.AAAA, newRec.AAAA) {
		rec.AAAA = newRec.AAAA
	}

	s.ips[domain] = rec
	s.pub.Publish(domain, nil)

	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *DoHNameServer) getMsgOptions() *dnsmessage.Resource {
	if len(s.clientIP) == 0 {
		return nil
	}

	var netmask int
	var family uint16

	if len(s.clientIP) == 4 {
		family = 1
		netmask = 24 // 24 for IPV4, 96 for IPv6
	} else {
		family = 2
		netmask = 96
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], family)
	b[2] = byte(netmask)
	b[3] = 0
	switch family {
	case 1:
		ip := s.clientIP.To4().Mask(net.CIDRMask(netmask, net.IPv4len*8))
		needLength := (netmask + 8 - 1) / 8 // division rounding up
		b = append(b, ip[:needLength]...)
	case 2:
		ip := s.clientIP.Mask(net.CIDRMask(netmask, net.IPv6len*8))
		needLength := (netmask + 8 - 1) / 8 // division rounding up
		b = append(b, ip[:needLength]...)
	}

	const EDNS0SUBNET = 0x08

	opt := new(dnsmessage.Resource)
	common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))

	opt.Body = &dnsmessage.OPTResource{
		Options: []dnsmessage.Option{
			{
				Code: EDNS0SUBNET,
				Data: b,
			},
		},
	}

	return opt
}

func (s *DoHNameServer) addPendingRequest(domain string, recType dnsmessage.Type) uint16 {

	id := uint16(atomic.AddUint32(&s.reqID, 1))
	s.Lock()
	defer s.Unlock()

	s.requests[id] = pendingRequest{
		domain:  domain,
		expire:  time.Now().Add(time.Second * 8),
		recType: recType,
	}

	return id
}

func (s *DoHNameServer) buildMsgs(domain string, option IPOption) []*dnsmessage.Message {
	qA := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	qAAAA := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}

	var msgs []*dnsmessage.Message

	if option.IPv4Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = s.addPendingRequest(domain, dnsmessage.TypeA)
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qA}
		if opt := s.getMsgOptions(); opt != nil {
			msg.Additionals = append(msg.Additionals, *opt)
		}
		msgs = append(msgs, msg)
	}

	if option.IPv6Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = s.addPendingRequest(domain, dnsmessage.TypeAAAA)
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qAAAA}
		if opt := s.getMsgOptions(); opt != nil {
			msg.Additionals = append(msg.Additionals, *opt)
		}
		msgs = append(msgs, msg)
	}

	return msgs
}

func (s *DoHNameServer) sendQuery(ctx context.Context, domain string, option IPOption) {
	newError(s.name, " querying DNS for: ", domain).AtWarning().WriteToLog(session.ExportIDToError(ctx))

	msgs := s.buildMsgs(domain, option)

	for _, msg := range msgs {
		b, _ := dns.PackMessage(msg)

		dnsCtx := context.Background()
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
		}
		dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
			Protocol: "https",
		})
		go func() {
			dnsCtx, cancel := context.WithTimeout(dnsCtx, 8*time.Second)
			defer cancel()
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				newError("failed to HTTPS response").Base(err).AtWarning().WriteToLog()
				return
			}
			s.HandleResponse(resp)
		}()
	}
}

func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {

	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	resp, err := s.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("DOH HTTPS server returned with non-OK code %d", resp.StatusCode)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func (s *DoHNameServer) findIPsForDomain(domain string, option IPOption) ([]net.IP, error) {
	s.RLock()
	record, found := s.ips[domain]
	s.RUnlock()

	if !found {
		return nil, errRecordNotFound
	}

	var ips []net.Address
	var lastErr error
	if option.IPv6Enable && record.AAAA != nil && record.AAAA.RCode == dnsmessage.RCodeSuccess {
		aaaa, err := record.AAAA.getIPs()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, aaaa...)
	}

	if option.IPv4Enable && record.A != nil && record.A.RCode == dnsmessage.RCodeSuccess {
		a, err := record.A.getIPs()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, a...)
	}

	if len(ips) > 0 {
		return toNetIP(ips), nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, dns_feature.ErrEmptyResponse
}

func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option IPOption) ([]net.IP, error) {
	// skip domain without any dot(.)
	if strings.Index(domain, ".") == -1 {
		return nil, newError("invalid domain name")
	}

	fqdn := Fqdn(domain)

	ips, err := s.findIPsForDomain(fqdn, option)
	if err != errRecordNotFound {
		newError(s.name, " cache HIT ", domain, ips).Base(err).AtWarning().WriteToLog()
		return ips, err
	}

	sub := s.pub.Subscribe(fqdn)
	defer sub.Close()

	s.RLock()
	_, isPending := s.pendingWait[fqdn]
	s.RUnlock()

	if !isPending {
		s.Lock()
		s.pendingWait[fqdn] = struct{}{}
		s.Unlock()
		s.sendQuery(ctx, fqdn, option)
	}

	for {
		ips, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
			return ips, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-sub.Wait():
		}
	}
}
