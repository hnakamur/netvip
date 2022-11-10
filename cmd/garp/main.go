package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/hnakamur/netvip"
	"github.com/urfave/cli/v2"
)

const (
	exitCodeRuntimeError = 1
	exitCodeUsageError   = 2
)

func main() {
	app := &cli.App{
		Name:    "garp",
		Version: Version(),
		Usage:   "send or receive GARP",
		Commands: []*cli.Command{
			{
				Name:    "serve",
				Aliases: []string{"s"},
				Usage:   "ensure a virtual IP address is added. does nothing if it is already added.",
				Flags: []cli.Flag{
					&cli.GenericFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Value:    &NetInterfaceValue{},
						Usage:    "the network interface to add a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.GenericFlag{
						Name:     "address",
						Aliases:  []string{"a"},
						Value:    &NetPrefixValue{},
						Usage:    "a virutal IP address (CIDR) to be added (e.g. 192.0.2.100/32)",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "label",
						Aliases: []string{"l"},
						Usage:   "a label for the virutal IP address (CIDR) (e.g. eth0 or eth0:0)",
					},
					&cli.BoolFlag{
						Name:  "add",
						Usage: "add VIP and send GARP",
					},
				},
				Action: func(cCtx *cli.Context) error {
					intf := cCtx.Generic("interface").(*NetInterfaceValue).intf
					cidr := cCtx.Generic("address").(*NetPrefixValue).prefix
					label := cCtx.String("label")
					add := cCtx.Bool("add")
					return serveCommand(intf, cidr, label, add)
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		cli.HandleExitCoder(err)
		fmt.Fprintf(app.ErrWriter, "\nError: %s\n", err)
		if strings.HasPrefix(err.Error(), "Required flag") {
			os.Exit(exitCodeUsageError)
		}
		os.Exit(exitCodeRuntimeError)
	}
}

// protocolARP is the uint16 EtherType representation of ARP (Address
// Resolution Protocol, RFC 826).
const protocolARP = 0x0806

func serveCommand(intf *net.Interface, cidr netip.Prefix, label string, add bool) error {
	log.Printf("serveCommand add=%+v", add)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.BindToDevice(fd, intf.Name); err != nil {
		return err
	}

	if add {
		go func() {
			if err := netvip.InterfaceAddPrefix(intf, cidr, label); err != nil {
				log.Printf("add vip: err=%s", err)
				return
			}
			log.Printf("added VIP")

			if err := netvip.SendGARP(intf, cidr.Addr()); err != nil {
				log.Printf("send GARP: err=%v", err)
				return
			}
			log.Printf("sent GARP")
		}()
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Printf("pc.ReadFrom: err=%v", err)
			continue
		}
		pkt, _, err := netvip.ParseARPPacket(buf[:n])
		if err != nil {
			// log.Printf("parsePacket: err=%v", err)
			continue
		}
		// log.Printf("pkt=%+v, frame=%+v", pkt, frame)
		if netvip.IsGARPPacket(pkt, cidr.Addr()) {
			log.Printf("received GARP packet, pkt=%+v", pkt)
		}
	}

	// return nil
}

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	return info.Main.Version
}

type NetInterfaceValue struct {
	intf *net.Interface
}

func (i *NetInterfaceValue) Set(value string) error {
	intf, err := net.InterfaceByName(value)
	if err != nil {
		return err
	}
	*i = NetInterfaceValue{intf: intf}
	return nil
}

func (i *NetInterfaceValue) String() string {
	if i.intf == nil {
		return ""
	}
	return i.intf.Name
}

func (i *NetInterfaceValue) Get() any {
	return i.intf
}

type NetPrefixValue struct {
	prefix     netip.Prefix
	hasBeenSet bool
}

func (p *NetPrefixValue) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = NetPrefixValue{
		prefix:     prefix,
		hasBeenSet: true,
	}
	return nil
}

func (p *NetPrefixValue) String() string {
	if p.hasBeenSet {
		return p.prefix.String()
	}
	return ""
}

func (p *NetPrefixValue) Get() any {
	if p.hasBeenSet {
		return p.prefix
	}
	return nil
}

func interfaceByName(name string) (*net.Interface, error) {
	intf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("no such network interface with name %q", name)
	}
	return intf, nil
}

func parseCIDR(cidrStr string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address prefix (CIDR): %s", cidrStr)
	}
	return pfx, nil
}
