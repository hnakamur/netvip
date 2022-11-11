//go:build amd64 || 386 || arm || arm64 || mipsle || mips64le || ppc64le || riscv64 || wasm

package netvip

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}
