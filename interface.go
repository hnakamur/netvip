package netvip

import (
	"errors"
	"net"
	"net/netip"
)

// InterfaceByIP return the interface which has a address prefix (CIDR)
// which contains the specified IP address.
func InterfaceByIP(addr netip.Addr) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range interfaces {
		if ok, err := HasAddr(&intf, addr); err != nil {
			return nil, err
		} else if ok {
			return &intf, nil
		}
	}
	return nil, errors.New("interface not found")
}

// HasAddr returns whether or not the interface has a address prefix (CIDR)
// which contains the specified IP address.
func HasAddr(intf *net.Interface, addr netip.Addr) (bool, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		cidr, err := netip.ParsePrefix(a.String())
		if err != nil {
			return false, err
		}
		if cidr.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}
