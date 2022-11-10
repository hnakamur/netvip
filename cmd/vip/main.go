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
					&cli.StringFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Usage:    "the network interface to add a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "address",
						Aliases:  []string{"a"},
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
						Usage:   "send GARP (Gratuitous ARP) packet when address is added or even when it is alreay added",
					},
					&cli.BoolFlag{
						Name:    "quiet",
						Aliases: []string{"q"},
						Usage:   "just exit with 0 if the interface has the address or 0 otherwise without print nothing",
					},
				},
				Action: func(cCtx *cli.Context) error {
					intf, err := interfaceByName(cCtx.String("interface"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					cidr, err := parseCIDR(cCtx.String("address"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					w := appWriterForQuietFlag(cCtx)
					return execAddCommand(intf, cidr, cCtx.String("label"), cCtx.Bool("garp"), w)
				},
			},
			{
				Name:    "del",
				Aliases: []string{"d"},
				Usage:   "ensure a virtual IP address is deleted. does nothing if it is already deleted.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Usage:    "the network interface to delete a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "address",
						Aliases:  []string{"a"},
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
					intf, err := interfaceByName(cCtx.String("interface"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					cidr, err := parseCIDR(cCtx.String("address"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					w := appWriterForQuietFlag(cCtx)
					return execDelCommand(intf, cidr, w, cCtx.Bool("watch"))
				},
			},
			{
				Name:  "has",
				Usage: "checks whether the specified interface has the virtual IP address prefix (CIDR).",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "interface",
						Aliases:  []string{"i"},
						Usage:    "the network interface to check if it has a virutal IP address (e.g. eth0)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "address",
						Aliases:  []string{"a"},
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
					intf, err := interfaceByName(cCtx.String("interface"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					cidr, err := parseCIDR(cCtx.String("address"))
					if err != nil {
						showErrAndCommandHelpAndExit(cCtx, err, exitCodeUsageError)
					}
					w := appWriterForQuietFlag(cCtx)
					return execHasCommand(intf, cidr, w)
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		var jerr *JustExitError
		if errors.As(err, &jerr) {
			os.Exit(jerr.ExitCode)
		} else {
			fmt.Fprintf(app.ErrWriter, "Error: %s\n", err.Error())
			os.Exit(exitCodeRuntimeError)
		}
	}
}

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	return info.Main.Version
}

func showErrAndCommandHelpAndExit(cCtx *cli.Context, err error, exitCode int) {
	fmt.Fprintf(cCtx.App.ErrWriter, "Error: %s\n\n", err.Error())
	cli.ShowCommandHelpAndExit(cCtx, cCtx.Command.Name, exitCode)
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

func appWriterForQuietFlag(cCtx *cli.Context) io.Writer {
	if cCtx.Bool("quiet") {
		return nil
	}
	return cCtx.App.Writer
}

func execAddCommand(intf *net.Interface, cidr netip.Prefix, label string, sendsGARP bool, appWriter io.Writer) error {
	has, err := netvip.InterfaceHasPrefix(intf, cidr)
	if err != nil {
		return err
	}
	if has {
		appWriterPrintf(appWriter, "interface %s already has address %s, does nothing\n", intf.Name, cidr)
	} else {
		err = netvip.InterfaceAddPrefix(intf, cidr, label)
		if err != nil {
			return err
		}
		appWriterPrintf(appWriter, "added address %s to interface %s\n", cidr, intf.Name)
	}

	if sendsGARP {
		if err := netvip.SendGARP(intf, cidr.Addr()); err != nil {
			return err
		}
		appWriterPrintf(appWriter, "sent GARP packet for address %s at interface %s\n", cidr, intf.Name)
	}

	return nil
}

func execDelCommand(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer, watch bool) error {
	if watch {
		return netvip.WatchGARP(context.TODO(), intf, cidr.Addr(), func(pkt *arp.Packet) error {
			if bytes.Equal(pkt.SenderHardwareAddr, intf.HardwareAddr) {
				appWriterPrintf(appWriter, "interface %s received GARP packet for VIP %s sent from itself.\n", intf.Name, cidr)
				return nil
			}
			return delVIPIfExists(intf, cidr, appWriter)
		})
	}

	return delVIPIfExists(intf, cidr, appWriter)
}

func delVIPIfExists(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer) error {
	has, err := netvip.InterfaceHasPrefix(intf, cidr)
	if err != nil {
		return err
	}
	if !has {
		appWriterPrintf(appWriter, "interface %s already does not have address %s, does nothing\n", intf.Name, cidr)
		return nil
	}

	err = netvip.InterfaceDelPrefix(intf, cidr)
	if err != nil {
		return err
	}
	appWriterPrintf(appWriter, "deleted address %s from interface %s\n", cidr, intf.Name)
	return nil
}

func execHasCommand(intf *net.Interface, cidr netip.Prefix, appWriter io.Writer) error {
	has, err := netvip.InterfaceHasPrefix(intf, cidr)
	if err != nil {
		return err
	}
	if has {
		appWriterPrintf(appWriter, "interface %s has address %s\n", intf.Name, cidr)
		return nil
	} else {
		appWriterPrintf(appWriter, "interface %s does not have address %s\n", intf.Name, cidr)
		return &JustExitError{ExitCode: 1}
	}
}

type JustExitError struct {
	ExitCode int
}

func (e *JustExitError) Error() string {
	return fmt.Sprintf("just exit with status %d", e.ExitCode)
}

func appWriterPrintf(w io.Writer, format string, a ...any) (n int, err error) {
	if w == nil {
		return 0, nil
	}
	return fmt.Fprintf(w, format, a...)
}
