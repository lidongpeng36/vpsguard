package firewall

import (
	"encoding/binary"
	"math/big"
	"net/netip"

	"github.com/google/nftables"
)

// prefixToElements converts a netip.Prefix (CIDR) to nftables interval set elements.
// Each CIDR becomes two elements: [start, end) where end is exclusive.
// e.g. 10.0.0.0/8 → {Key: 10.0.0.0} + {Key: 11.0.0.0, IntervalEnd: true}
func prefixToElements(p netip.Prefix) (start, end nftables.SetElement) {
	p = p.Masked() // normalize
	addr := p.Addr()
	startBytes := addrBytes(addr)

	start = nftables.SetElement{
		Key:         startBytes,
		IntervalEnd: false,
	}

	endAddr := prefixEndAddr(p)
	end = nftables.SetElement{
		Key:         addrBytes(endAddr),
		IntervalEnd: true,
	}

	return start, end
}

// prefixEndAddr returns the first address AFTER the prefix range (exclusive end).
// e.g. 10.0.0.0/8 → 11.0.0.0, 192.168.1.0/24 → 192.168.2.0
func prefixEndAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	addr := p.Addr()
	bits := p.Bits()

	if addr.Is4() {
		a4 := addr.As4()
		hostBits := uint(32 - bits)
		ipNum := binary.BigEndian.Uint32(a4[:])
		endNum := ipNum + (1 << hostBits)
		var end [4]byte
		binary.BigEndian.PutUint32(end[:], endNum)
		return netip.AddrFrom4(end)
	}

	// IPv6: use big.Int for 128-bit arithmetic
	a16 := addr.As16()
	ipBig := new(big.Int).SetBytes(a16[:])
	hostBits := uint(128 - bits)
	add := new(big.Int).Lsh(big.NewInt(1), hostBits)
	endBig := new(big.Int).Add(ipBig, add)
	endBytes := endBig.Bytes()
	var end [16]byte
	copy(end[16-len(endBytes):], endBytes)
	return netip.AddrFrom16(end)
}

// addrBytes returns the raw bytes for an address (4 bytes for IPv4, 16 for IPv6).
func addrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		a4 := addr.As4()
		return a4[:]
	}
	a16 := addr.As16()
	return a16[:]
}

// prefixesToElements converts a slice of prefixes into nftables set elements
// suitable for an interval set.
func prefixesToElements(prefixes []netip.Prefix) []nftables.SetElement {
	if len(prefixes) == 0 {
		return nil
	}
	elements := make([]nftables.SetElement, 0, len(prefixes)*2)
	for _, p := range prefixes {
		start, end := prefixToElements(p)
		elements = append(elements, start, end)
	}
	return elements
}

// nativeUint32 encodes a uint32 in native byte order.
func nativeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}
