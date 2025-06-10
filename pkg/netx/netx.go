package netx

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func LocalAddressByInterfaceName(interfaceName string) (net.Addr, error) {
	i, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := i.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if naddr, ok := addr.(*net.IPNet); ok {
			// leaving port set to zero to let kernel pick
			return &net.TCPAddr{IP: naddr.IP}, nil
		}
	}

	return nil, fmt.Errorf("cannot create local address for interface %q", interfaceName)
}

func LocalOutboundIP() string {
	server := "119.29.29.29:53"
	conn, err := net.DialTimeout("udp", server, time.Second)
	if err != nil {
		log.Println(err)
		return ""
	}
	defer conn.Close()
	return strings.SplitN(conn.LocalAddr().String(), ":", 2)[0]
}
