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
	"v2ray.com/core/common/dice"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol/dns"
	"v2ray.com/core/common/session"
	"v2ray.com/core/common/signal/pubsub"
	"v2ray.com/core/common/task"
	"v2ray.com/core/features/routing"
)

type dohRequest struct {
	reqType dnsmessage.Type
	domain  string
	start   time.Time
	msg     *dnsmessage.Message
}

// DoHNameServer implimented DNS over HTTPS (RFC8484) Wire Format,
// which is compatiable with traditional dns over udp(RFC1035),
// thus most of the DOH implimentation is copied from udpns.go
type DoHNameServer struct {
	sync.RWMutex
	dispatcher routing.Dispatcher
	dohDests   []net.Destination
	ips        map[string]record
	pub        *pubsub.Service
	cleanup    *task.Periodic
	reqID      uint32
	clientIP   net.IP
	httpClient *http.Client
	dohURL     string
	name       string
}

func NewDoHNameServer(dests []net.Destination, dohHost string, dispatcher routing.Dispatcher, clientIP net.IP) *DoHNameServer {

	s := NewDoHLocalNameServer(dohHost, clientIP)
	s.name = "DOH:" + dohHost
	s.dispatcher = dispatcher
	s.dohDests = dests

	// Dispatched connection will be closed (interupted) after each request
	// This makes DOH inefficient without a keeped-alive connection
	// See: core/app/proxyman/outbound/handler.go:113
	// Using mux (https request wrapped in a stream layer) improves the situation,
	// but if the outbound is not vmess protocol, the connection problem persiststed.
	// Recommand to use NewDoHLocalNameServer if the DOH is performed on a normal network
	tr := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         s.dohDispatchedDial,
	}

	dispatchedClient := &http.Client{
		Transport: tr,
		Timeout:   16 * time.Second,
	}

	s.httpClient = dispatchedClient
	return s
}

func NewDoHLocalNameServer(dohHost string, clientIP net.IP) *DoHNameServer {
	s := &DoHNameServer{
		httpClient: http.DefaultClient,
		ips:        make(map[string]record),
		clientIP:   clientIP,
		pub:        pubsub.NewService(),
		name:       "DOHL:" + dohHost,
		dohURL:     fmt.Sprintf("https://%s/dns-query", dohHost),
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

func (s *DoHNameServer) dohDispatchedDial(ctx context.Context, network, addr string) (net.Conn, error) {

	dest := s.dohDests[dice.Roll(len(s.dohDests))]

	link, err := s.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}
	return net.NewConnection(
		net.ConnectionInputMulti(link.Writer),
		net.ConnectionOutputMulti(link.Reader),
	), nil
}

func (s *DoHNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 {
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

	return nil
}

func (s *DoHNameServer) HandleResponse(req *dohRequest, payload []byte) {

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

	now := time.Now()
	var ipRecExpire time.Time
	if header.RCode != dnsmessage.RCodeSuccess {
		// A default TTL, maybe a negtive cache
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
				newError("failed to parse answer section for domain: ", req.domain).Base(err).WriteToLog()
			}
			break
		}
		ttl := header.TTL
		if ttl < 600 {
			// at least 10 mins TTL
			ttl = 600
		}
		expire := now.Add(time.Duration(ttl) * time.Second)
		ipRecord.Expire = expire

		if header.Type != req.reqType {
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
				newError("failed to parse A record for domain: ", req.domain).Base(err).WriteToLog()
				break L
			}
			ipRecord.IP = append(ipRecord.IP, net.IPAddress(ans.A[:]))
		case dnsmessage.TypeAAAA:
			ans, err := parser.AAAAResource()
			if err != nil {
				newError("failed to parse A record for domain: ", req.domain).Base(err).WriteToLog()
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
	switch req.reqType {
	case dnsmessage.TypeA:
		rec.A = ipRecord
	case dnsmessage.TypeAAAA:
		rec.AAAA = ipRecord
	}

	elapsed := time.Since(req.start)
	newError(s.name, " updating domain:", req.domain, " -> ", ipRecord.IP, " ", elapsed).AtWarning().WriteToLog()
	s.updateIP(req.domain, rec)
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

func (s *DoHNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *DoHNameServer) buildMsgs(domain string, option IPOption) []*dohRequest {
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

	var reqs []*dohRequest
	now := time.Now()

	if option.IPv4Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = s.newReqID()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qA}
		if opt := s.getMsgOptions(); opt != nil {
			msg.Additionals = append(msg.Additionals, *opt)
		}
		reqs = append(reqs, &dohRequest{
			reqType: dnsmessage.TypeA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	if option.IPv6Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = s.newReqID()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qAAAA}
		if opt := s.getMsgOptions(); opt != nil {
			msg.Additionals = append(msg.Additionals, *opt)
		}
		reqs = append(reqs, &dohRequest{
			reqType: dnsmessage.TypeAAAA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	return reqs
}

func (s *DoHNameServer) sendQuery(ctx context.Context, domain string, option IPOption) {
	newError(s.name, " querying DNS for: ", domain).AtWarning().WriteToLog(session.ExportIDToError(ctx))

	reqs := s.buildMsgs(domain, option)

	for _, req := range reqs {

		dnsCtx := context.Background()
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
		}
		dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
			Protocol: "https",
		})
		go func(r *dohRequest) {
			dnsCtx, cancel := context.WithTimeout(dnsCtx, 8*time.Second)
			defer cancel()
			b, _ := dns.PackMessage(r.msg)
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				newError("failed to HTTPS response").Base(err).AtWarning().WriteToLog()
				return
			}
			s.HandleResponse(r, resp)
		}(req)
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

	return nil, errRecordNotFound
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

	s.sendQuery(ctx, fqdn, option)

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
