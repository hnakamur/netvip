package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/hnakamur/netvip"
	"github.com/mdlayher/arp"
	"github.com/urfave/cli/v2"
)

const (
	exitCodeRuntimeError = 1
	exitCodeUsageError   = 2
)

func main() {
	app := &cli.App{
		Name:    "vip",
		Version: Version(),
		Usage:   "Add or delete virtual IP address",
		Commands: []*cli.Command{
			{
				Name:    "add",
				Aliases: []string{"a"},
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
						Name:    "garp",
						Aliases: []string{"g"},
						Value:   true,
						Usage:   "send GARP (Gratuitous ARP) packet when address is added or even when it is alreay added",
					},
					&cli.BoolFlag{
						Name:    "quiet",
						Aliases: []string{"q"},
						Usage:   "just exit with 0 if the interface has the address or 0 otherwise without print nothing",
					},
				},
				Action: func(cCtx *cli.Context) error {
					intf := cCtx.Generic("interface").(*NetInterfaceValue).intf
					cidr := *cCtx.Generic("address").(*NetPrefixValue).prefix
					w := appWriterForQuietFlag(cCtx)
					return execAddCommand(intf, cidr, cCtx.String("label"), cCtx.Bool("garp"), w)
				},
			},
			{
				Name:    "del",
				Aliases: []string{"d"},
				Usage:   "ensure a virtual IP address is deleted. does nothing if it is already deleted.",
				Flags: []cli.Flag{
					&cli.GenericFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Value:    &NetInterfaceValue{},
						Usage:    "the network interface to delete a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.GenericFlag{
						Name:     "address",
						Aliases:  []string{"a"},
						Value:    &NetPrefixValue{},
						Usage:    "a virutal IP address (CIDR) to be deleted (e.g. 192.0.2.100/32)",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "quiet",
						Aliases: []string{"q"},
						Usage:   "just exit with 0 if the interface has the address or 0 otherwise without print nothing",
					},
					&cli.BoolFlag{
						Name:    "watch",
						Aliases: []string{"w"},
						Usage:   "watch GARP packets and delete VIP everytime GARP packet is received",
					},
				},
				Action: func(cCtx *cli.Context) error {
					intf := cCtx.Generic("interface").(*NetInterfaceValue).intf
					cidr := *cCtx.Generic("address").(*NetPrefixValue).prefix
					w := appWriterForQuietFlag(cCtx)
					return execDelCommand(intf, cidr, w, cCtx.Bool("watch"))
				},
			},
			{
				Name:  "has",
				Usage: "checks whether the specified interface has the virtual IP address prefix (CIDR).",
				Flags: []cli.Flag{
					&cli.GenericFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Value:    &NetInterfaceValue{},
						Usage:    "the network interface to check if it has a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.GenericFlag{
						Name:     "address",
						Aliases:  []string{"a"},
						Value:    &NetPrefixValue{},
						Usage:    "a virutal IP address (CIDR) to be checked (e.g. 192.0.2.100/32)",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "quiet",
						Aliases: []string{"q"},
						Usage:   "just exit with 0 if the interface has the address or 0 otherwise without print nothing",
					},
				},
				Action: func(cCtx *cli.Context) error {
					intf := cCtx.Generic("interface").(*NetInterfaceValue).intf
					cidr := *cCtx.Generic("address").(*NetPrefixValue).prefix
					w := appWriterForQuietFlag(cCtx)
					return execHasCommand(intf, cidr, w)
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

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	return info.Main.Version
}

func appWriterForQuietFlag(cCtx *cli.Context) io.Writer {
	if cCtx.Bool("quiet") {
		return io.Discard
	}
	return cCtx.App.Writer
}

func execAddCommand(intf *net.Interface, cidr netip.Prefix, label string, sendsGARP bool, appWriter io.Writer) error {
	if err := netvip.InterfaceAddPrefix(intf, cidr, label); err != nil {
		if !os.IsExist(err) {
			return err
		}
		fmt.Fprintf(appWriter, "address %s is already added to interface %s\n", cidr, intf.Name)
	} else {
		fmt.Fprintf(appWriter, "added address %s to interface %s\n", cidr, intf.Name)
	}

	if sendsGARP {
		if err := netvip.SendGARP(intf, cidr.Addr()); err != nil {
			return err
		}
		fmt.Fprintf(appWriter, "sent GARP packet for address %s at interface %s\n", cidr, intf.Name)
	}

	return nil
}

func execDelCommand(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer, watch bool) error {
	if watch {
		return netvip.WatchGARP(context.TODO(), cidr.Addr(), func(pkt *arp.Packet) error {
			if bytes.Equal(pkt.SenderHardwareAddr, intf.HardwareAddr) {
				fmt.Fprintf(appWriter, "interface %s received GARP packet for VIP %s sent from itself.\n", intf.Name, cidr)
				return nil
			}
			return deleteVIP(intf, cidr, appWriter)
		})
	}

	return deleteVIP(intf, cidr, appWriter)
}

func deleteVIP(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer) error {
	if err := netvip.InterfaceDelPrefix(intf, cidr); err != nil {
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return err
		}
		fmt.Fprintf(appWriter, "address %s is aleady deleted from interface %s\n", cidr, intf.Name)
	} else {
		fmt.Fprintf(appWriter, "deleted address %s from interface %s\n", cidr, intf.Name)
	}
	return nil
}

func execHasCommand(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer) error {
	has, err := netvip.InterfaceHasPrefix(intf, cidr)
	if err != nil {
		return err
	}
	if has {
		fmt.Fprintf(appWriter, "interface %s has address %s\n", intf.Name, cidr)
		return nil
	} else {
		fmt.Fprintf(appWriter, "interface %s does not have address %s\n", intf.Name, cidr)
		return cli.Exit("", exitCodeRuntimeError)
	}
}

type NetPrefixValue struct {
	prefix *netip.Prefix
}

func (p *NetPrefixValue) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	p.prefix = &prefix
	return nil
}

func (p *NetPrefixValue) String() string {
	if p.prefix == nil {
		return ""
	}
	return p.prefix.String()
}

func (p *NetPrefixValue) Get() any {
	return p.prefix
}

type NetInterfaceValue struct {
	intf *net.Interface
}

func (i *NetInterfaceValue) Set(value string) error {
	intf, err := net.InterfaceByName(value)
	if err != nil {
		return err
	}
	i.intf = intf
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
