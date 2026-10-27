package managementasset

import (
	"bytes"
	_ "embed"
)

//go:embed privacy.js
var emailPrivacyScript []byte

//go:embed provider_presets.js
var providerPresetsScript []byte

// WithCustomizations adds local display features without modifying the downloaded panel.
func WithCustomizations(html []byte) []byte {
	insertion := bytes.Index(bytes.ToLower(html), []byte("</head>"))
	if insertion < 0 {
		insertion = len(html)
	}
	var page bytes.Buffer
	page.Grow(len(html) + len(emailPrivacyScript) + len(providerPresetsScript) + 64)
	page.Write(html[:insertion])
	page.WriteString("<script>\n")
	page.Write(emailPrivacyScript)
	page.WriteString("\n</script>\n<script>\n")
	page.Write(providerPresetsScript)
	page.WriteString("\n</script>\n")
	page.Write(html[insertion:])
	return page.Bytes()
}
