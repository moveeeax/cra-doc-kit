package textfmt

import "testing"

func TestCount(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0 findings"},
		{1, "1 finding"},
		{2, "2 findings"},
	}
	for _, tc := range cases {
		if got := Count(tc.n, "finding", "findings"); got != tc.want {
			t.Errorf("Count(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestHaveAndIs(t *testing.T) {
	if Have(1) != "has" || Have(0) != "have" || Have(2) != "have" {
		t.Error("Have() does not agree with the subject count")
	}
	if Is(1) != "is" || Is(0) != "are" || Is(2) != "are" {
		t.Error("Is() does not agree with the subject count")
	}
}
