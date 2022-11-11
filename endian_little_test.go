//go:build amd64 || 386 || arm || arm64 || mipsle || mips64le || ppc64le || riscv64 || wasm

package netvip

import "testing"

func TestHtons(t *testing.T) {
	input := uint16(0x0102)
	if got, want := htons(input), uint16(0x0201); got != want {
		t.Errorf("result mismatch, got=0x%04x, want=0x%04x", got, want)
	}
}
