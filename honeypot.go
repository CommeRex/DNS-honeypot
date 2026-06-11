package main

import (
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

const upstreamResolver = "8.8.8.8:53"

// Global rate limiter and classifier
var (
	rateLimiter *RateLimiter
	classifier  *Classifier
)

// handlePacket is called in its own goroutine for every incoming UDP packet.
// localIP is the destination IP of the incoming packet (from IP_PKTINFO),
// used to send the reply from the correct interface.
func handlePacket(pc *ipv4.PacketConn, src *net.UDPAddr, data []byte, localIP net.IP, ifIndex int) {
	now := time.Now()

	// 1. Parse
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return // not a valid DNS packet; ignore silently
	}
	if msg.Response || len(msg.Question) == 0 {
		return
	}

	q := msg.Question[0]
	domain    := q.Name
	queryType := dns.TypeToString[q.Qtype]
	ednsSize  := extractEDNS0Size(msg)
	srcIP     := src.IP.String()

	// 2. Classifier
	classifier.Observe(srcIP, domain, queryType, now)

	// 3. Rate limiter
	allowed, justBlocked := rateLimiter.Check(srcIP)
	if !allowed {
		if justBlocked {
			writeLog(LogEntry{
				EventType:     "rate_limited",
				Timestamp:     now.UTC().Format(time.RFC3339Nano),
				SourceIP:      srcIP,
				SourcePort:    src.Port,
				QueriedDomain: domain,
				QueryType:     queryType,
				EDNSPayload:   ednsSize,
				RequestSize:   len(data),
				ResponseSize:  0, // no response was sent
			})
		}
		return
	}

	// 4. Respond and log
	_, responseSize := forwardAndRespond(pc, src, msg, localIP, ifIndex)

	writeLog(LogEntry{
		EventType:     "request",
		Timestamp:     now.UTC().Format(time.RFC3339Nano),
		SourceIP:      srcIP,
		SourcePort:    src.Port,
		QueriedDomain: domain,
		QueryType:     queryType,
		EDNSPayload:   ednsSize,
		RequestSize:   len(data),
		ResponseSize:  responseSize,
	})
}

func extractEDNS0Size(msg *dns.Msg) uint16 {
	if opt := msg.IsEdns0(); opt != nil {
		return opt.UDPSize()
	}
	return 0
}

// forwardAndRespond forwards the query to the real upstream resolver and sends
// the response back to src, using localIP as the source address.
func forwardAndRespond(pc *ipv4.PacketConn, src *net.UDPAddr, query *dns.Msg, localIP net.IP, ifIndex int) ([]byte, int) {
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	response, _, err := client.Exchange(query, upstreamResolver)
	if err != nil {
		log.Printf("upstream error for %s: %v", query.Question[0].Name, err)
		servfail := new(dns.Msg)
		servfail.SetReply(query)
		servfail.Rcode = dns.RcodeServerFailure
		packed, _ := servfail.Pack()
		sendFrom(pc, packed, src, localIP, ifIndex)
		return packed, len(packed)
	}

	if opt := query.IsEdns0(); opt != nil {
		response.SetEdns0(opt.UDPSize(), false)
	}

	packed, err := response.Pack()
	if err != nil {
		log.Printf("failed to pack response: %v", err)
		return nil, 0
	}

	sendFrom(pc, packed, src, localIP, ifIndex)
	return packed, len(packed)
}

// sendFrom writes b to dst, forcing the reply to leave from localIP on the
// interface identified by ifIndex.
func sendFrom(pc *ipv4.PacketConn, b []byte, dst *net.UDPAddr, localIP net.IP, ifIndex int) {
	cm := &ipv4.ControlMessage{}
	if localIP != nil {
		cm.Src = localIP
	}
	if ifIndex != 0 {
		cm.IfIndex = ifIndex
	}
	// DEBUG: log what we are telling the kernel about the outgoing reply.
	log.Printf("reply to %s: src=%v ifindex=%d", dst, localIP, ifIndex)
	if _, err := pc.WriteTo(b, cm, dst); err != nil {
		log.Printf("failed to send response to %s: %v", dst, err)
	}
}
