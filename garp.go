package netvip

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
)

var macAddrBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// SendGARP sends a GARP (Gratuitous ARP) packet.
// See https://wiki.wireshark.org/Gratuitous_ARP for GARP.
func SendGARP(intf *net.Interface, addr netip.Addr) error {
	c, err := arp.Dial(intf)
	if err != nil {
		return err
	}
	defer c.Close()

	p, err := arp.NewPacket(arp.OperationRequest, intf.HardwareAddr, addr,
		macAddrBroadcast, addr)
	if err != nil {
		return err
	}
	err = c.WriteTo(p, macAddrBroadcast)
	if err != nil {
		return err
	}
	return nil
}

var (
	// errInvalidARPPacket is returned when an ethernet frame does not
	// indicate that an ARP packet is contained in its payload.
	errInvalidARPPacket = errors.New("invalid ARP packet")
)

func ParseARPPacket(buf []byte) (*arp.Packet, *ethernet.Frame, error) {
	f := new(ethernet.Frame)
	if err := f.UnmarshalBinary(buf); err != nil {
		return nil, nil, err
	}

	// Ignore frames which do not have ARP EtherType
	if f.EtherType != ethernet.EtherTypeARP {
		return nil, nil, errInvalidARPPacket
	}

	p := new(arp.Packet)
	if err := p.UnmarshalBinary(f.Payload); err != nil {
		return nil, nil, err
	}
	return p, f, nil
}

func IsGARPPacket(p *arp.Packet, vip netip.Addr) bool {
	return p.Operation == arp.OperationRequest &&
		p.SenderIP.Compare(vip) == 0 &&
		bytes.Equal(p.TargetHardwareAddr, macAddrBroadcast) &&
		p.TargetIP.Compare(vip) == 0
}

func WatchGARP(ctx context.Context, addr netip.Addr, callback func(*arp.Packet) error) error {
	const typ = syscall.SOCK_RAW | syscall.SOCK_CLOEXEC
	proto := int(htons(uint16(syscall.ETH_P_ARP)))
	fd, err := syscall.Socket(syscall.AF_PACKET, typ, proto)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tv := &syscall.Timeval{Sec: 1, Usec: 0}
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, tv); err != nil {
			return err
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		pkt, _, err := ParseARPPacket(buf[:n])
		if err != nil {
			return err
		}
		if IsGARPPacket(pkt, addr) {
			if err := callback(pkt); err != nil {
				return err
			}
		}
	}
}
