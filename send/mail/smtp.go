package mail

import (
	"context"
	"errors"
	"github.com/go-gomail/gomail"
	"log"
	"os"
)

type smtpClient struct {
	idp idp

	username string
	password string
	host     string
	port     int
}

func (s smtpClient) validate() error {
	if err := s.idp.validate(); err != nil {
		return err
	}
	if s.username == "" {
		return errors.New("smtp username cannot be empty, environment variable SMTP_USERNAME not set")
	}
	if s.password == "" {
		return errors.New("smtp password cannot be empty, environment variable SMTP_PASSWORD not set")
	}
	if s.host == "" {
		return errors.New("smtp host cannot be empty, environment variable SMTP_HOST not set")
	}
	if s.port == 0 {
		return errors.New("smtp port cannot be empty")
	}
	return nil
}

func NewSMTPClient(idpAddr, idpName, mailFrom string) *smtpClient {
	client := &smtpClient{
		idp: idp{
			addr:     idpAddr,
			name:     idpName,
			mailFrom: mailFrom,
		},
		username: os.Getenv("IDP_SMTP_USERNAME"),
		password: os.Getenv("IDP_SMTP_PASSWORD"),
		host:     os.Getenv("IDP_SMTP_HOST"),
		port:     465,
	}
	if err := client.validate(); err != nil {
		log.Fatal(err.Error())
	}
	return client
}

func (s *smtpClient) SendResetPasswordToken(ctx context.Context, email, args string) error {
	mail := newResetPasswordEmail(s.idp, email, args)
	return s.send(mail)
}

func (s *smtpClient) send(m *gomail.Message) error {
	dialer := gomail.NewDialer(s.host, s.port, s.username, s.password)
	return dialer.DialAndSend(m)
}
