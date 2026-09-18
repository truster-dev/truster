// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	texttemplate "text/template"
	"time"
)

//go:embed pages/*.html email/*
var embeddedTemplates embed.FS

// Manager owns the compiled page and email templates.
type Manager struct {
	pages        map[string]*template.Template
	emailHTML    *template.Template
	emailText    *texttemplate.Template
	emailSubject *texttemplate.Template
	public       map[string]publicAsset
}

// effective reads an overlay template when present and otherwise uses the embedded template.
func effective(dir, path string) ([]byte, error) {
	if dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err == nil {
			return b, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read template %s: %w", path, err)
		}
	}
	return embeddedTemplates.ReadFile(path)
}

// Load compiles each page with the effective common layout and test-renders all templates.
func Load(dir string) (*Manager, error) {
	layout, err := effective(dir, "pages/layout.html")
	if err != nil {
		return nil, err
	}
	public, err := loadPublic(dir)
	if err != nil {
		return nil, err
	}
	m := &Manager{pages: make(map[string]*template.Template), public: public}
	pageData := map[string]any{
		"selector": SelectorData{Title: "Sign in", Screen: "login", State: "opaque", SiteKey: "site-key", Connectors: []ConnectorData{{ID: "google", DisplayName: "Google", URL: "/select/google?state=opaque"}, {ID: "email", DisplayName: "Email", Email: true}}},
		"otp":      OTPData{Title: "Verify email", ChallengeID: "opaque", Message: "A code was sent.", Email: "user@example.com", ExpiresIn: 5 * time.Minute, ExpiresAt: time.Now().Add(5 * time.Minute)},
		"error":    ErrorData{"Login failed", "Unable to sign in."},
		"identity": IdentityData{Title: "Choose an email", Token: "opaque", Emails: []EmailData{{Address: "primary@example.com", Verified: true, Primary: true}, {Address: "other@example.com"}}},
		"consent":  ConsentData{Title: "Allow offline access", State: "opaque", ClientID: "client"},
		"grants":   GrantsData{Title: "Active grants", Email: "user@example.com", Grants: []GrantData{{SID: "sid", ClientID: "client", Mode: "session", ActionToken: "opaque", Email: "user@example.com", CreatedAt: time.Now(), LastUsedAt: time.Now(), ExpiresAt: time.Now()}}},
	}
	for name, data := range pageData {
		page, readErr := effective(dir, "pages/"+name+".html")
		if readErr != nil {
			return nil, readErr
		}
		t, parseErr := template.New("layout").Option("missingkey=error").Parse(string(layout))
		if parseErr == nil {
			_, parseErr = t.Parse(string(page))
		}
		if parseErr != nil {
			return nil, fmt.Errorf("parse page %s: %w", name, parseErr)
		}
		var out bytes.Buffer
		if renderErr := t.ExecuteTemplate(&out, "layout", data); renderErr != nil {
			return nil, fmt.Errorf("render page %s: %w", name, renderErr)
		}
		m.pages[name] = t
	}
	htmlLayout, err := effective(dir, "email/layout.html")
	if err != nil {
		return nil, err
	}
	htmlBytes, err := effective(dir, "email/otp.html")
	if err != nil {
		return nil, err
	}
	textLayout, err := effective(dir, "email/layout.txt")
	if err != nil {
		return nil, err
	}
	textBytes, err := effective(dir, "email/otp.txt")
	if err != nil {
		return nil, err
	}
	subjectBytes, err := effective(dir, "email/otp.subject.txt")
	if err != nil {
		return nil, err
	}
	m.emailHTML, err = template.New("layout").Option("missingkey=error").Parse(string(htmlLayout))
	if err == nil {
		_, err = m.emailHTML.Parse(string(htmlBytes))
	}
	if err != nil {
		return nil, fmt.Errorf("parse HTML email templates: %w", err)
	}
	m.emailText, err = texttemplate.New("layout").Option("missingkey=error").Parse(string(textLayout))
	if err == nil {
		_, err = m.emailText.Parse(string(textBytes))
	}
	if err != nil {
		return nil, fmt.Errorf("parse text email templates: %w", err)
	}
	m.emailSubject, err = texttemplate.New("subject").Option("missingkey=error").Parse(string(subjectBytes))
	if err != nil {
		return nil, fmt.Errorf("parse email subject template: %w", err)
	}
	var out bytes.Buffer
	testEmailData := OTPEmailData{Code: "12345678", ExpiresAt: time.Date(2026, time.July, 27, 12, 34, 0, 0, time.UTC), ExpiresIn: 5 * time.Minute}
	if err = m.emailHTML.ExecuteTemplate(&out, "layout", testEmailData); err != nil {
		return nil, fmt.Errorf("render email/otp.html: %w", err)
	}
	out.Reset()
	if err = m.emailText.ExecuteTemplate(&out, "layout", testEmailData); err != nil {
		return nil, fmt.Errorf("render email/otp.txt: %w", err)
	}
	if _, err = m.RenderEmailSubject(testEmailData); err != nil {
		return nil, fmt.Errorf("render email/otp.subject.txt: %w", err)
	}
	return m, nil
}

// Validate checks that all effective templates compile and render.
func Validate(dir string) error { _, err := Load(dir); return err }

// RenderPage renders a named HTML page.
func (m *Manager) RenderPage(w io.Writer, name string, data any) error {
	t, ok := m.pages[name]
	if !ok {
		return fmt.Errorf("unknown page %q", name)
	}
	return t.ExecuteTemplate(w, "layout", data)
}

// RenderEmail renders an OTP email in the requested format.
func (m *Manager) RenderEmail(w io.Writer, format string, data OTPEmailData) error {
	if format == "html" {
		return m.emailHTML.ExecuteTemplate(w, "layout", data)
	}
	if format == "text" {
		return m.emailText.ExecuteTemplate(w, "layout", data)
	}
	return fmt.Errorf("unknown email format %q", format)
}

// RenderEmailSubject renders and validates an OTP email subject.
func (m *Manager) RenderEmailSubject(data OTPEmailData) (string, error) {
	var out bytes.Buffer
	if err := m.emailSubject.ExecuteTemplate(&out, "subject", data); err != nil {
		return "", err
	}
	subject := out.String()
	if subject == "" || strings.ContainsAny(subject, "\r\n") {
		return "", fmt.Errorf("email subject must be non-empty and single-line")
	}
	return subject, nil
}
