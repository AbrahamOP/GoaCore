package handlers

import (
	"encoding/json"
	"html/template"
	"strings"
)

// TemplateFuncMap is the single source of truth for the template functions the
// server registers. cmd/server and the render tests both use it, so a new
// function can never be added to one and forgotten in the other (the bug that
// let "iconSrc" ship undefined to the template parse).
func TemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			// Escape </script> and <!-- to prevent injection in <script> blocks.
			s := strings.ReplaceAll(string(a), "</", `<\/`)
			s = strings.ReplaceAll(s, "<!--", `<\!--`)
			return template.JS(s), nil
		},
		// iconSrc marks an app icon URL as safe for an <img src> context.
		// html/template otherwise rewrites every data: URL (even data:image/png)
		// to "#ZgotmplZ", so app logos never render. We allow ONLY raster image
		// data: URIs and http(s); everything else — javascript:, data:text/html,
		// AND data:image/svg+xml (an SVG can carry <script>) — is dropped to "".
		// Defence in depth: an <img src> never executes JS, only an admin can set
		// icon_url, and the page CSP restricts img-src to 'self' data:.
		"iconSrc": func(s string) template.URL {
			allowed := []string{"data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp", "https://", "http://"}
			for _, p := range allowed {
				if strings.HasPrefix(s, p) {
					return template.URL(s)
				}
			}
			return ""
		},
	}
}
