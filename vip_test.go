package netvip

import (
	"flag"
	"net"
	"net/netip"
	"testing"
)

var testInterfName = flag.String("interf", "enp1s0f1", "network interface name for test")
var testVIPStr = flag.String("vip", "192.168.2.248/32", "virtual IP address prefix (CIDR) for test")
var testLabel = flag.String("label", "enp1s0f1:0", "label for virtual address for test")

func TestAddDelAddr(t *testing.T) {
	intf, err := net.InterfaceByName(*testInterfName)
	if err != nil {
		t.Fatal(err)
	}
	vip := netip.MustParsePrefix(*testVIPStr)

	if err := InterfaceAddPrefix(intf, vip, *testLabel); err != nil {
		t.Fatal(err)
	}
	if got, err := InterfaceHasPrefix(intf, vip); err != nil {
		t.Fatal(err)
	} else if want := true; got != want {
		t.Errorf("result of InterfaceHasPrefix after AddAddr mimatch, got=%v, want=%v", got, want)
	}

	if err := SendGARP(intf, vip.Addr()); err != nil {
		t.Fatal(err)
	}

	if got, err := InterfaceByPrefix(vip); err != nil {
		t.Fatal(err)
	} else if want := intf; got.Index != want.Index {
		t.Errorf("index mismatch for InterfaceByPrefix, got=%d, want=%d", got.Index, want.Index)
	}

	if got, err := InterfaceHasPrefix(intf, vip); err != nil {
		t.Fatal(err)
	} else if want := true; got != want {
		t.Errorf("result mismatch for InterfaceHasPrefix, got=%v, want=%v", got, want)
	}

	if err := InterfaceDelPrefix(intf, vip); err != nil {
		t.Fatal(err)
	}
	if got, err := InterfaceHasPrefix(intf, vip); err != nil {
		t.Fatal(err)
	} else if want := false; got != want {
		t.Errorf("result of InterfaceHasPrefix after DelAddr mimatch, got=%v, want=%v", got, want)
	}
}
