// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/truster-dev/truster/v2/internal/templates"
	"golang.org/x/term"
)

const devReloadInterval = 500 * time.Millisecond

// templateServer serves live-reloading template previews.
type templateServer struct {
	dir       string
	mu        sync.RWMutex
	manager   *templates.Manager
	loadErr   error
	revision  uint64
	signature [sha256.Size]byte
}

// newTemplateServer creates and initially loads a preview server.
func newTemplateServer(dir string) *templateServer {
	s := &templateServer{dir: dir}
	s.reload(true)
	return s
}

// reload refreshes templates when their directory signature changes.
func (s *templateServer) reload(force bool) {
	signature := templateDirSignature(s.dir)
	s.mu.RLock()
	unchanged := signature == s.signature
	s.mu.RUnlock()
	if !force && unchanged {
		return
	}
	manager, err := templates.Load(s.dir)
	s.mu.Lock()
	s.signature = signature
	s.loadErr = err
	if err == nil {
		s.manager = manager
	}
	s.revision++
	s.mu.Unlock()
}

// templateDirSignature hashes the paths and contents in a template directory.
func templateDirSignature(dir string) [sha256.Size]byte {
	hash := sha256.New()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			_, _ = io.WriteString(hash, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write(contents)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		_, _ = io.WriteString(hash, err.Error())
	}
	var signature [sha256.Size]byte
	copy(signature[:], hash.Sum(nil))
	return signature
}

// watch periodically checks for template changes until cancellation.
func (s *templateServer) watch(ctx context.Context) {
	ticker := time.NewTicker(devReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reload(false)
		}
	}
}

// ServeHTTP renders the requested mock preview or development endpoint.
func (s *templateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	manager, loadErr, revision := s.manager, s.loadErr, s.revision
	s.mu.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/__truster_dev/revision" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprint(w, revision)
		return
	}
	if loadErr != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		body := []byte("<!doctype html><title>Template error</title><h1>Template error</h1><pre>" + html.EscapeString(loadErr.Error()) + "</pre></body>")
		_, _ = w.Write(injectReload(body, revision))
		return
	}
	if manager == nil {
		http.Error(w, "templates unavailable", http.StatusInternalServerError)
		return
	}
	pageData := templates.PageData{
		Request:     templates.RequestData{Method: r.Method, Host: r.Host, Path: r.URL.Path},
		IssuerURL:   "https://auth.example.com",
		HomepageURL: "https://app.example.com",
	}
	if r.Method == http.MethodPost {
		s.handleMockPost(w, r)
		return
	}
	if r.Method == http.MethodHead {
		manager.HandlePublic(w, r, pageData)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var output bytes.Buffer
	contentType := "text/html; charset=utf-8"
	var err error
	switch r.URL.Path {
	case "/":
		output.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Truster template previews</title></head><body><main><h1>Truster template previews</h1><ul><li><a target="_blank" href="/pages/selector.html">Connector selector</a></li><li><a target="_blank" href="/pages/identity.html">Identity selector</a></li><li><a target="_blank" href="/pages/otp.html">OTP entry</a></li><li><a target="_blank" href="/pages/error.html">Error page</a></li><li><a target="_blank" href="/email/otp.html">HTML email</a></li><li><a target="_blank" href="/email/otp.txt">Plain-text email</a></li></ul></main></body></html>`)
	case "/pages/selector.html":
		err = manager.RenderPage(&output, "selector", templates.SelectorData{
			PageData: pageData, Title: "Sign in", State: "mock-state", Connectors: []templates.ConnectorData{
				{ID: "google", DisplayName: "Google", URL: "#google"},
				{ID: "github", DisplayName: "GitHub", URL: "#github"},
				{ID: "email", DisplayName: "Email", Email: true},
			},
		})
	case "/pages/otp.html":
		err = manager.RenderPage(&output, "otp", templates.OTPData{PageData: pageData, Title: "Verify email", ChallengeID: "mock-challenge", Message: "A code was sent.", Email: "user@example.com", ExpiresIn: 5 * time.Minute, ExpiresAt: time.Now().Add(5 * time.Minute)})
	case "/pages/identity.html":
		err = manager.RenderPage(&output, "identity", templates.IdentityData{PageData: pageData, Title: "Choose an email", Token: "mock-token", Emails: []templates.EmailData{{Address: "primary@example.com", Verified: true, Primary: true}, {Address: "other@example.com"}}})
	case "/pages/error.html":
		err = manager.RenderPage(&output, "error", templates.ErrorData{PageData: pageData, Title: "Login failed", Message: "This is a mock error message."})
	case "/email/otp.html":
		err = manager.RenderEmail(&output, "html", templates.OTPEmailData{Code: "12345678", ExpiresAt: time.Now().UTC().Add(5 * time.Minute), ExpiresIn: 5 * time.Minute})
	case "/email/otp.txt":
		contentType = "text/plain; charset=utf-8"
		err = manager.RenderEmail(&output, "text", templates.OTPEmailData{Code: "12345678", ExpiresAt: time.Now().UTC().Add(5 * time.Minute), ExpiresIn: 5 * time.Minute})
	default:
		manager.HandlePublic(w, r, pageData)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if contentType == "text/html; charset=utf-8" {
		_, _ = w.Write(injectReload(output.Bytes(), revision))
		return
	}
	_, _ = w.Write(output.Bytes())
}

// handleMockPost redirects mock form submissions between preview pages.
func (*templateServer) handleMockPost(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/email/start", "/email/resend":
		http.Redirect(w, r, "/pages/otp.html", http.StatusSeeOther)
	case "/email/verify":
		http.Redirect(w, r, "/pages/selector.html", http.StatusSeeOther)
	case "/identity/select":
		http.Redirect(w, r, "/pages/selector.html", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// injectReload adds a browser-side revision poller to an HTML response.
func injectReload(body []byte, revision uint64) []byte {
	script := []byte(`<script>(()=>{const r="` + strconv.FormatUint(revision, 10) + `";setInterval(async()=>{try{if(await(await fetch("/__truster_dev/revision",{cache:"no-store"})).text()!=r)location.reload()}catch{}},500)})()</script>`)
	if bytes.Contains(body, []byte("</body>")) {
		return bytes.Replace(body, []byte("</body>"), append(script, []byte("</body>")...), 1)
	}
	return append(body, script...)
}

// Run serves template previews until the context is canceled or the process receives an interrupt.
func Run(ctx context.Context, input io.Reader, output io.Writer, templatesDir, listenAddr string) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	preview := newTemplateServer(templatesDir)
	go preview.watch(ctx)
	server := &http.Server{Addr: listenAddr, Handler: preview, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen for template development server: %w", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	url := "http://" + listener.Addr().String() + "/"
	_, _ = fmt.Fprintf(output, "Template development server: %s\n", url)
	_, _ = fmt.Fprintln(output, "Previews:")
	_, _ = fmt.Fprintln(output, "  /                       Preview index")
	_, _ = fmt.Fprintln(output, "  /pages/selector.html    Connector selector")
	_, _ = fmt.Fprintln(output, "  /pages/identity.html    Identity selector")
	_, _ = fmt.Fprintln(output, "  /pages/otp.html         OTP entry")
	_, _ = fmt.Fprintln(output, "  /pages/error.html       Error page")
	_, _ = fmt.Fprintln(output, "  /email/otp.html         HTML email")
	_, _ = fmt.Fprintln(output, "  /email/otp.txt          Plain-text email")
	_, _ = fmt.Fprintln(output, "Press O to open this in your browser.")
	restoreTerminal := makeTerminalRaw(input)
	defer restoreTerminal()
	go handleInput(ctx, cancel, input, output, url, openBrowser)
	select {
	case err := <-errCh:
		if err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	}
}

// makeTerminalRaw enables single-key terminal input and returns a restore function.
func makeTerminalRaw(input io.Reader) func() {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return func() {}
	}
	state, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(int(file.Fd()), state) }
}

// handleInput handles browser-open and interrupt keystrokes.
func handleInput(ctx context.Context, cancel context.CancelFunc, input io.Reader, output io.Writer, url string, opener func(string) error) {
	buffer := make([]byte, 1)
	for {
		if _, err := input.Read(buffer); err != nil {
			return
		}
		switch buffer[0] {
		case 'o', 'O':
			if err := opener(url); err != nil {
				_, _ = fmt.Fprintf(output, "Unable to open browser: %v\r\n", err)
			}
		case 3:
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// openBrowser starts the platform browser for a URL.
func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start browser command: %w", err)
	}
	return command.Process.Release()
}
