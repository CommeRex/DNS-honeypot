package main

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func main() {
	if err := initLogger("honeypot.jsonl"); err != nil {
		log.Fatalf("could not open log file: %v", err)
	}
	defer closeLogger()

	rateLimiter = newRateLimiter()
	classifier  = newClassifier()

	// Bind UDP socket on port 53.
	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("failed to listen on UDP port 53: %v\n"+
			"(hint: sudo ./honeypot, or change Port to 5353 for local testing)", err)
	}
	defer conn.Close()

	// make responses always leave from the
	// correct interface instead of the kernel's default-route interface.
	pc := ipv4.NewPacketConn(conn)

	if err := pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		log.Fatalf("failed to enable IP_PKTINFO: %v", err)
	}

	fmt.Println("DNS honeypot listening on UDP port 53")
	fmt.Printf("  rate limit : %d req / %s  →  blocked for %s\n",
		maxRequests, windowSize, blockDuration)
	fmt.Printf("  attack threshold : %d consecutive requests / %s gap\n",
		attackThreshold, gapTimeout)
	fmt.Println("  logs written to  : honeypot.jsonl")

	buf := make([]byte, 4096)
	for {
		// ReadFrom returns the control message (cm) which contains cm.Dst,
		// the destination IP of the incoming packet.
		n, cm, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Extract the local IP this packet arrived on. If for any reason
		// IP_PKTINFO is unavailable, localIP stays nil and forwardAndRespond
		// falls back to letting the kernel pick (the old behaviour).
		var localIP net.IP
		var ifIndex int
		if cm != nil {
			if cm.Dst != nil {
				localIP = cm.Dst
			}
			ifIndex = cm.IfIndex
		}

		go handlePacket(pc, src.(*net.UDPAddr), pkt, localIP, ifIndex)
	}
}
