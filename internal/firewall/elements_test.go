package firewall

import (
	"net/netip"
	"testing"
)

func TestPrefixEndAddrIPv4(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{"10.0.0.0/8", "11.0.0.0"},
		{"192.168.1.0/24", "192.168.2.0"},
		{"1.0.0.0/24", "1.0.1.0"},
		{"172.16.0.0/12", "172.32.0.0"},
		{"10.0.0.1/32", "10.0.0.2"},
		{"0.0.0.0/0", "0.0.0.0"}, // wraps around (entire range)
		{"255.255.255.0/24", "0.0.0.0"}, // wraps around
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := prefixEndAddr(p)
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("prefixEndAddr(%s) = %s, want %s", tt.prefix, got, want)
			}
		})
	}
}

func TestPrefixEndAddrIPv6(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{"2001:db8::/32", "2001:db9::"},
		{"2001:200::/32", "2001:201::"},
		{"fe80::/10", "fec0::"},
		{"::1/128", "::2"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := prefixEndAddr(p)
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("prefixEndAddr(%s) = %s, want %s", tt.prefix, got, want)
			}
		})
	}
}

func TestPrefixToElements(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/8")
	start, end := prefixToElements(p)

	if start.IntervalEnd {
		t.Error("start element should not be IntervalEnd")
	}
	if !end.IntervalEnd {
		t.Error("end element should be IntervalEnd")
	}

	// Start should be 10.0.0.0
	wantStart := []byte{10, 0, 0, 0}
	if !bytesEqual(start.Key, wantStart) {
		t.Errorf("start.Key = %v, want %v", start.Key, wantStart)
	}

	// End should be 11.0.0.0
	wantEnd := []byte{11, 0, 0, 0}
	if !bytesEqual(end.Key, wantEnd) {
		t.Errorf("end.Key = %v, want %v", end.Key, wantEnd)
	}
}

func TestPrefixToElementsIPv6(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/32")
	start, end := prefixToElements(p)

	if len(start.Key) != 16 {
		t.Errorf("IPv6 start key should be 16 bytes, got %d", len(start.Key))
	}
	if len(end.Key) != 16 {
		t.Errorf("IPv6 end key should be 16 bytes, got %d", len(end.Key))
	}

	// Start: 2001:0db8:0000:...
	if start.Key[0] != 0x20 || start.Key[1] != 0x01 {
		t.Errorf("unexpected start key: %x", start.Key)
	}
	// End: 2001:0db9:0000:...
	if end.Key[2] != 0x0d || end.Key[3] != 0xb9 {
		t.Errorf("unexpected end key: %x", end.Key)
	}
}

func TestPrefixesToElements(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	elements := prefixesToElements(prefixes)
	// 2 prefixes × 2 elements each = 4
	if len(elements) != 4 {
		t.Fatalf("got %d elements, want 4", len(elements))
	}

	// Check alternating start/end pattern
	if elements[0].IntervalEnd {
		t.Error("elements[0] should be start")
	}
	if !elements[1].IntervalEnd {
		t.Error("elements[1] should be end")
	}
	if elements[2].IntervalEnd {
		t.Error("elements[2] should be start")
	}
	if !elements[3].IntervalEnd {
		t.Error("elements[3] should be end")
	}
}

func TestPrefixesToElementsEmpty(t *testing.T) {
	elements := prefixesToElements(nil)
	if elements != nil {
		t.Errorf("got %v, want nil", elements)
	}
}

func TestPrefixesToElementsSingle32(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
	}
	elements := prefixesToElements(prefixes)
	if len(elements) != 2 {
		t.Fatalf("got %d elements, want 2", len(elements))
	}
	wantStart := []byte{1, 2, 3, 4}
	wantEnd := []byte{1, 2, 3, 5}
	if !bytesEqual(elements[0].Key, wantStart) {
		t.Errorf("start = %v, want %v", elements[0].Key, wantStart)
	}
	if !bytesEqual(elements[1].Key, wantEnd) {
		t.Errorf("end = %v, want %v", elements[1].Key, wantEnd)
	}
}

func TestAddrBytes(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	b4 := addrBytes(v4)
	if len(b4) != 4 {
		t.Errorf("IPv4 should be 4 bytes, got %d", len(b4))
	}

	v6 := netip.MustParseAddr("2001:db8::1")
	b6 := addrBytes(v6)
	if len(b6) != 16 {
		t.Errorf("IPv6 should be 16 bytes, got %d", len(b6))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
