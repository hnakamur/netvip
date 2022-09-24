package netvip

import (
	"errors"
	"net"
	"net/netip"
)

// InterfaceByIP return the interface which has a address prefix (CIDR)
// which equals to the specified IP address.
func InterfaceByPrefix(pfx netip.Prefix) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range interfaces {
		if ok, err := InterfaceHasPrefix(&intf, pfx); err != nil {
			return nil, err
		} else if ok {
			return &intf, nil
		}
	}
	return nil, errors.New("interface not found")
}

// InterfaceHasPrefix returns whether or not the interface has a address prefix (CIDR)
// which equals to the specified address prefix.
func InterfaceHasPrefix(intf *net.Interface, pfx netip.Prefix) (bool, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		cidr, err := netip.ParsePrefix(a.String())
		if err != nil {
			return false, err
		}
		if prefixEqual(cidr, pfx) {
			return true, nil
		}
	}
	return false, nil
}

func prefixEqual(pfx1, pfx2 netip.Prefix) bool {
	return pfx1.Addr().Compare(pfx2.Addr()) == 0 && pfx1.Bits() == pfx2.Bits()
}
