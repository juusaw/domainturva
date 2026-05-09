package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTP is a Notifier that sends an email via STARTTLS.
type SMTP struct {
	N        string
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string

	DialTimeout time.Duration
}

func NewSMTP(name, host string, port int, user, pass, from string, to []string) *SMTP {
	return &SMTP{
		N:           name,
		Host:        host,
		Port:        port,
		Username:    user,
		Password:    pass,
		From:        from,
		To:          to,
		DialTimeout: 10 * time.Second,
	}
}

func (s *SMTP) Name() string { return s.N }

func (s *SMTP) Notify(ctx context.Context, a Alert) error {
	subject := fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(a.Severity)), a.Title, a.SiteName)
	var body bytes.Buffer
	fmt.Fprintf(&body, "Site: %s\nType: %s\nSeverity: %s\nTime: %s\n\n%s\n",
		a.SiteName, a.Type, a.Severity, a.At.UTC().Format(time.RFC3339), a.Message)
	if len(a.Details) > 0 {
		body.WriteString("\nDetails:\n")
		for k, v := range a.Details {
			fmt.Fprintf(&body, "  %s: %v\n", k, v)
		}
	}

	msg := buildMIME(s.From, s.To, subject, body.String())

	addr := net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
	dialer := &net.Dialer{Timeout: s.DialTimeout}

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			done <- result{err}
			return
		}
		client, err := smtp.NewClient(conn, s.Host)
		if err != nil {
			conn.Close()
			done <- result{err}
			return
		}
		defer client.Quit()

		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
				done <- result{err}
				return
			}
		}
		if s.Username != "" {
			auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
			if err := client.Auth(auth); err != nil {
				done <- result{err}
				return
			}
		}
		if err := client.Mail(s.From); err != nil {
			done <- result{err}
			return
		}
		for _, to := range s.To {
			if err := client.Rcpt(to); err != nil {
				done <- result{err}
				return
			}
		}
		w, err := client.Data()
		if err != nil {
			done <- result{err}
			return
		}
		if _, err := w.Write(msg); err != nil {
			done <- result{err}
			return
		}
		if err := w.Close(); err != nil {
			done <- result{err}
			return
		}
		done <- result{nil}
	}()

	select {
	case r := <-done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func buildMIME(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=\"utf-8\"\r\n")
	fmt.Fprintf(&b, "\r\n")
	b.WriteString(body)
	return b.Bytes()
}
