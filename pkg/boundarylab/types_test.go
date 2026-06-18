package boundarylab_test

import (
	"encoding/json"
	"testing"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

func TestAction_ZeroValue(t *testing.T) {
	var a boundarylab.Action
	if a != boundarylab.ActionDeny {
		t.Fatalf("zero value of Action must be ActionDeny (0), got %d", a)
	}
}

func TestSecurityLabel_ZeroIsMinPrivilege(t *testing.T) {
	var label boundarylab.SecurityLabel
	if label.Confidentiality != 0 || label.Integrity != 0 || label.Category != 0 {
		t.Fatal("zero-value SecurityLabel must have all fields = 0 (minimum privilege)")
	}
}

func TestAction_MarshalJSON(t *testing.T) {
	cases := []struct {
		action boundarylab.Action
		want   string
	}{
		{boundarylab.ActionDeny, `"deny"`},
		{boundarylab.ActionAllow, `"allow"`},
		{boundarylab.ActionRequireApproval, `"require_approval"`},
		{boundarylab.ActionAudit, `"audit"`},
	}
	for _, c := range cases {
		got, err := json.Marshal(c.action)
		if err != nil {
			t.Fatalf("MarshalJSON(%v): %v", c.action, err)
		}
		if string(got) != c.want {
			t.Errorf("MarshalJSON(%v) = %s, want %s", c.action, got, c.want)
		}
	}
}

func TestAction_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		wire string
		want boundarylab.Action
	}{
		{`"deny"`, boundarylab.ActionDeny},
		{`"allow"`, boundarylab.ActionAllow},
		{`"require_approval"`, boundarylab.ActionRequireApproval},
		{`"audit"`, boundarylab.ActionAudit},
	}
	for _, c := range cases {
		var a boundarylab.Action
		if err := json.Unmarshal([]byte(c.wire), &a); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", c.wire, err)
		}
		if a != c.want {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", c.wire, a, c.want)
		}
	}
}

func TestAction_UnmarshalJSON_Unknown(t *testing.T) {
	var a boundarylab.Action
	if err := json.Unmarshal([]byte(`"unknown"`), &a); err != nil {
		t.Fatalf("UnmarshalJSON(unknown): unexpected error %v", err)
	}
	if a != boundarylab.ActionDeny {
		t.Errorf("UnmarshalJSON(unknown) = %v, want ActionDeny (fail-secure)", a)
	}
}

func TestDecision_LabelsIsScalar(t *testing.T) {
	d := boundarylab.Decision{
		Labels: boundarylab.SecurityLabel{Confidentiality: 1, Integrity: 1},
	}
	_ = d.Labels.Confidentiality
}
