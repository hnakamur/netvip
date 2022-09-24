package netvip

import (
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
)

var macBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// SendGARP sends a GARP (Gratuitous ARP) packet.
// See https://wiki.wireshark.org/Gratuitous_ARP for GARP.
func SendGARP(intf *net.Interface, addr netip.Addr) error {
	c, err := arp.Dial(intf)
	if err != nil {
		return err
	}
	defer c.Close()

	p, err := arp.NewPacket(arp.OperationRequest, intf.HardwareAddr, addr,
		macBroadcast, addr)
	if err != nil {
		return err
	}
	err = c.WriteTo(p, macBroadcast)
	if err != nil {
		return err
	}
	return nil
}
