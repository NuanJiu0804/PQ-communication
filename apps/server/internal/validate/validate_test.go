package validate

import "testing"

func TestUUID(t *testing.T) {
	cases := map[string]bool{
		"3f2b8c4e-1a2b-4c3d-9e8f-0123456789ab": true,
		"3F2B8C4E-1A2B-4C3D-9E8F-0123456789AB": true,
		"":                                     false,
		"not-a-uuid":                           false,
		"3f2b8c4e1a2b4c3d9e8f0123456789ab":     false,
		"3f2b8c4e-1a2b-4c3d-9e8f-0123456789ab' OR 1=1": false,
	}
	for in, want := range cases {
		if got := UUID(in); got != want {
			t.Errorf("UUID(%q) = %v, want %v", in, got, want)
		}
	}
}
