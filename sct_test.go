package main

import "testing"

func TestParseSCTList(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{
			name: "empty",
			in:   nil,
			want: 0,
		},
		{
			name: "single SCT (no outer OCTET STRING wrapper)",
			// list_length=0x0030 (48 bytes); one SCT of length 0x002e (46)
			in: append(
				[]byte{0x00, 0x30, 0x00, 0x2e},
				make([]byte, 46)...,
			),
			want: 1,
		},
		{
			name: "two SCTs with outer OCTET STRING wrapper (short form)",
			// OCTET STRING: tag 0x04, length 0x44 (68); content = list_length 0x0042 + 2× (SCT_length 0x001f + 31 bytes)
			in: append(
				[]byte{0x04, 0x44, 0x00, 0x42, 0x00, 0x1f},
				append(
					make([]byte, 31),
					append([]byte{0x00, 0x1f}, make([]byte, 31)...)...,
				)...,
			),
			want: 2,
		},
		{
			name: "malformed: list_length larger than body",
			in:   []byte{0x00, 0xff, 0x00, 0x01, 0xab},
			want: 0,
		},
	}
	for _, c := range cases {
		got := parseSCTList(c.in)
		if got != c.want {
			t.Errorf("%s: parseSCTList = %d, want %d", c.name, got, c.want)
		}
	}
}
