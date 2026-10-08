// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/truster-dev/truster/v3/internal/config"
)

// Sender sends the application email messages supported by Truster.
type Sender interface {
	SendOTP(ctx context.Context, to, code string, expiresAt time.Time) error
}

// Credentials contains SMTP authentication credentials.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ParseCredentials parses and validates JSON-encoded SMTP credentials.
func ParseCredentials(raw string) (Credentials, error) {
	var credentials Credentials
	err := json.Unmarshal([]byte(raw), &credentials)
	if err != nil || credentials.Username == "" || credentials.Password == "" {
		return credentials, fmt.Errorf("invalid SMTP credentials")
	}
	return credentials, nil
}

// SMTPMailer sends multipart messages over SMTP.
type SMTPMailer struct {
	config      config.SMTPConfig
	credentials Credentials
}

// NewSMTPMailer creates an SMTP transport.
func NewSMTPMailer(config config.SMTPConfig, credentials Credentials) *SMTPMailer {
	return &SMTPMailer{config: config, credentials: credentials}
}

// send sends one multipart plain-text and HTML message.
func (m *SMTPMailer) send(ctx context.Context, to, subject, textBody, htmlBody string) error {
	if strings.ContainsAny(to+m.config.FromAddress+m.config.FromName+subject, "\r\n") {
		return fmt.Errorf("invalid mail header")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	boundaryBytes := make([]byte, 18)
	if _, err := rand.Read(boundaryBytes); err != nil {
		return fmt.Errorf("generate MIME boundary: %w", err)
	}
	boundary := "truster-" + base64.RawURLEncoding.EncodeToString(boundaryBytes)
	from := (&mail.Address{Name: m.config.FromName, Address: m.config.FromAddress}).String()
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n", from, to, mime.QEncoding.Encode("utf-8", subject), boundary)
	fmt.Fprintf(&message, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n--%s--\r\n", boundary, textBody, boundary, htmlBody, boundary)

	dialer := net.Dialer{Timeout: 10 * time.Second}
	address := net.JoinHostPort(m.config.Host, fmt.Sprint(m.config.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.config.Host}
	var connection net.Conn
	var err error
	if m.config.TLSMode == "implicit" {
		connection, err = tls.DialWithDialer(&dialer, "tcp", address, tlsConfig)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect SMTP: %w", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	client, err := smtp.NewClient(connection, m.config.Host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer func() { _ = client.Close() }()
	if m.config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not advertise STARTTLS")
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if m.credentials.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", m.credentials.Username, m.credentials.Password, m.config.Host)); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	if err = client.Mail(m.config.FromAddress); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = writer.Write(message.Bytes()); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
