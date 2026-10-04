package proto

import "testing"

func TestTemplateURIComponents(t *testing.T) {
	for _, raw := range []string{
		"1https://server/ip/{target}/{ipproto}/",
		"+https://server/ip/{target}/{ipproto}/",
		".https://server/ip/{target}/{ipproto}/",
		"https://server?query=/ip/{target}/{ipproto}/",
		"https://server#fragment/ip/{target}/{ipproto}/",
		"https://server/ip#fragment/{target}/{ipproto}/",
		"https://server/ip?target={target}#fragment/{ipproto}",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseTemplate(raw); err == nil {
				t.Fatal("accepted variables outside path/query or an invalid scheme")
			}
		})
	}
	// A fixed fragment has no template variables and is not sent in the
	// HTTP request target. %23 remains part of the path, not a fragment.
	for _, raw := range []string{
		"https://server/ip/%23/{target}{?ipproto}#fixed",
		"HtTpS+test.1://server/ip/%23/{target}{?ipproto}",
	} {
		tpl, err := ParseTemplate(raw)
		if err != nil {
			t.Fatal(err)
		}
		path := tpl.Expand(map[string]string{"target": "192.0.2.1", "ipproto": "6"})
		if path != "/ip/%23/192.0.2.1?ipproto=6" {
			t.Fatalf("request target %q contains a fragment or lost an encoded literal", path)
		}
		vars, ok := tpl.Match(path)
		if !ok || vars["target"] != "192.0.2.1" || vars["ipproto"] != "6" {
			t.Fatalf("expanded request no longer matches: %v, %v", vars, ok)
		}
	}
}
