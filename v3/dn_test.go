package ldap

import (
	"reflect"
	"testing"
)

func TestSuccessfulDNParsing(t *testing.T) {
	testcases := map[string]DN{
		"": {[]*RelativeDN{}},
		"cn=Jim\\2C \\22Hasse Hö\\22 Hansson!,dc=dummy,dc=com": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "Jim, \"Hasse Hö\" Hansson!"}}},
			{[]*AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]*AttributeTypeAndValue{{"dc", "com"}}}}},
		"UID=jsmith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"UID", "jsmith"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}}}},
		"OU=Sales+CN=J. Smith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"OU", "Sales"},
				{"CN", "J. Smith"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}}}},
		"1.3.6.1.4.1.1466.0=#04024869": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}}}},
		"1.3.6.1.4.1.1466.0=#04024869,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}}}},
		"CN=Lu\\C4\\8Di\\C4\\87": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}}}},
		"  CN  =  Lu\\C4\\8Di\\C4\\87  ": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}}}},
		`   A   =   1   ,   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"A", "1"}}},
			{[]*AttributeTypeAndValue{{"B", "2"}}}}},
		`   A   =   1   +   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"A", "1"},
				{"B", "2"}}}}},
		`   \ \ A\ \    =   \ \ 1\ \    ,   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"  A  ", "  1  "}}},
			{[]*AttributeTypeAndValue{{"  B  ", "  2  "}}}}},
		`   \ \ A\ \    =   \ \ 1\ \    +   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"  A  ", "  1  "},
				{"  B  ", "  2  "}}}}},

		`cn=john.doe;dc=example,dc=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "john.doe"}}},
			{[]*AttributeTypeAndValue{{"dc", "example"}}},
			{[]*AttributeTypeAndValue{{"dc", "net"}}}}},

		// Escaped `;` should not be treated as RDN
		`cn=john.doe\;weird name,dc=example,dc=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "john.doe;weird name"}}},
			{[]*AttributeTypeAndValue{{"dc", "example"}}},
			{[]*AttributeTypeAndValue{{"dc", "net"}}}}},
	}

	for test, answer := range testcases {
		dn, err := ParseDN(test)
		if err != nil {
			t.Errorf(err.Error())
			continue
		}
		if !reflect.DeepEqual(dn, &answer) {
			t.Errorf("Parsed DN %s is not equal to the expected structure", test)
			t.Logf("Expected:")
			for _, rdn := range answer.RDNs {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
			t.Logf("Actual:")
			for _, rdn := range dn.RDNs {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
		}
	}
}

func TestErrorDNParsing(t *testing.T) {
	testcases := map[string]string{
		"*":                       "DN ended with incomplete type, value pair",
		"cn=Jim\\0Test":           "failed to decode escaped character: encoding/hex: invalid byte: U+0054 'T'",
		"cn=Jim\\0":               "got corrupted escaped character",
		"DC=example,=net":         "DN ended with incomplete type, value pair",
		"1=#0402486":              "failed to decode BER encoding: encoding/hex: odd length hex string",
		"test,DC=example,DC=com":  "incomplete type, value pair",
		"=test,DC=example,DC=com": "incomplete type, value pair",
	}

	for test, answer := range testcases {
		_, err := ParseDN(test)
		if err == nil {
			t.Errorf("Expected %s to fail parsing but succeeded\n", test)
		} else if err.Error() != answer {
			t.Errorf("Unexpected error on %s:\n%s\nvs.\n%s\n", test, answer, err.Error())
		}
	}
}

func TestDNEqual(t *testing.T) {
	testcases := []struct {
		A     string
		B     string
		Equal bool
	}{
		// Exact match
		{"", "", true},
		{"o=A", "o=A", true},
		{"o=A", "o=B", false},

		{"o=A,o=B", "o=A,o=B", true},
		{"o=A,o=B", "o=A,o=C", false},

		{"o=A+o=B", "o=A+o=B", true},
		{"o=A+o=B", "o=A+o=C", false},

		// Case mismatch in type is ignored
		{"o=A", "O=A", true},
		{"o=A,o=B", "o=A,O=B", true},
		{"o=A+o=B", "o=A+O=B", true},

		// Case mismatch in value is significant
		{"o=a", "O=A", false},
		{"o=a,o=B", "o=A,O=B", false},
		{"o=a+o=B", "o=A+O=B", false},

		// Multi-valued RDN order mismatch is ignored
		{"o=A+o=B", "O=B+o=A", true},
		// Number of RDN attributes is significant
		{"o=A+o=B", "O=B+o=A+O=B", false},

		// Missing values are significant
		{"o=A+o=B", "O=B+o=A+O=C", false}, // missing values matter
		{"o=A+o=B+o=C", "O=B+o=A", false}, // missing values matter

		// Whitespace tests
		// Matching
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John Doe, ou=People, dc=sun.com",
			true,
		},
		// Difference in leading/trailing chars is ignored
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John Doe,ou=People,dc=sun.com",
			true,
		},
		// Difference in values is significant
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John  Doe, ou=People, dc=sun.com",
			false,
		},
		// Test parsing of `;` for separating RDNs
		{"cn=john;dc=example,dc=com", "cn=john,dc=example,dc=com", true}, // missing values matter
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Equal, a.Equal(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
		if expected, actual := tc.Equal, b.Equal(a); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
	}
}

func TestDNEqualFold(t *testing.T) {
	testcases := []struct {
		A     string
		B     string
		Equal bool
	}{
		// Match on case insensitive
		{"o=A", "o=a", true},
		{"o=A,o=b", "o=a,o=B", true},
		{"o=a+o=B", "o=A+o=b", true},
		{
			"cn=users,ou=example,dc=com",
			"cn=Users,ou=example,dc=com",
			true,
		},

		// Match on case insensitive and case mismatch in type
		{"o=A", "O=a", true},
		{"o=A,o=b", "o=a,O=B", true},
		{"o=a+o=B", "o=A+O=b", true},
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Equal, a.EqualFold(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
		if expected, actual := tc.Equal, b.EqualFold(a); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
	}
}

func TestDNAncestor(t *testing.T) {
	testcases := []struct {
		A        string
		B        string
		Ancestor bool
	}{
		// Exact match returns false
		{"", "", false},
		{"o=A", "o=A", false},
		{"o=A,o=B", "o=A,o=B", false},
		{"o=A+o=B", "o=A+o=B", false},

		// Mismatch
		{"ou=C,ou=B,o=A", "ou=E,ou=D,ou=B,o=A", false},

		// Descendant
		{"ou=C,ou=B,o=A", "ou=E,ou=C,ou=B,o=A", true},
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Ancestor, a.AncestorOf(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
	}
}
