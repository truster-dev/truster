// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truster-dev/truster/v3/internal/config"
)

// TestSMTPMailerWithoutCredentials verifies omitted credentials skip SMTP authentication.
func TestSMTPMailerWithoutCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	commands := make(chan []string, 1)
	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer func() { _ = connection.Close() }()
		if _, writeErr := fmt.Fprint(connection, "220 localhost ESMTP\r\n"); writeErr != nil {
			serverErrors <- writeErr
			return
		}

		var received []string
		inData := false
		scanner := bufio.NewScanner(connection)
		for scanner.Scan() {
			line := scanner.Text()
			if inData {
				if line == "." {
					inData = false
					if _, writeErr := fmt.Fprint(connection, "250 queued\r\n"); writeErr != nil {
						serverErrors <- writeErr
						return
					}
				}
				continue
			}
			received = append(received, line)
			var writeErr error
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_, writeErr = fmt.Fprint(connection, "250 localhost\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				_, writeErr = fmt.Fprint(connection, "250 OK\r\n")
			case line == "DATA":
				inData = true
				_, writeErr = fmt.Fprint(connection, "354 send data\r\n")
			case line == "QUIT":
				_, writeErr = fmt.Fprint(connection, "221 bye\r\n")
				commands <- received
				serverErrors <- writeErr
				return
			default:
				_, writeErr = fmt.Fprint(connection, "500 unexpected command\r\n")
			}
			if writeErr != nil {
				serverErrors <- writeErr
				return
			}
		}
		serverErrors <- scanner.Err()
	}()

	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	mailer := NewSMTPMailer(config.SMTPConfig{Host: host, Port: port, FromAddress: "auth@example.com", TLSMode: "plaintext"}, Credentials{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = mailer.send(ctx, "person@example.com", "Demo code", "Code: 12345678", "<p>Code: 12345678</p>"); err != nil {
		t.Fatalf("send without SMTP credentials: %v", err)
	}
	if err = <-serverErrors; err != nil {
		t.Fatalf("SMTP test server: %v", err)
	}
	for _, command := range <-commands {
		if strings.HasPrefix(command, "AUTH") {
			t.Fatalf("unexpected SMTP authentication command: %q", command)
		}
	}
}
