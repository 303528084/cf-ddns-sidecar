package ddns

import "testing"

func TestSplitDomain(t *testing.T) {
	cases := []struct {
		domain, root, wantRoot, wantRec string
	}{
		{"cf.example.com", "example.com", "example.com", "cf"},
		{"example.com", "example.com", "example.com", "@"},
		{"a.b.example.com", "example.com", "example.com", "a.b"},
		{"example.com.", "example.com", "example.com", "@"},
		{"cf.example.com", "", "cf.example.com", "@"},
	}
	for _, c := range cases {
		r, rec := splitDomain(c.domain, c.root)
		if r != c.wantRoot || rec != c.wantRec {
			t.Errorf("splitDomain(%q,%q) = (%q,%q)，期望 (%q,%q)",
				c.domain, c.root, r, rec, c.wantRoot, c.wantRec)
		}
	}
}
