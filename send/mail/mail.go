package mail

import (
	"errors"
	"fmt"
	"github.com/go-gomail/gomail"
)

type idp struct {
	addr     string
	name     string
	mailFrom string
}

func (i idp) validate() error {
	if i.addr == "" {
		return errors.New("idp address cannot be empty")
	}
	if i.name == "" {
		return errors.New("idp name cannot be empty")
	}
	if i.mailFrom == "" {
		return errors.New("\"reply to\" cannot be empty, set environment variable \"IDP_REPLY_TO\"")
	}
	return nil
}

func newResetPasswordEmail(idp idp, email, args string) *gomail.Message {
	uri := fmt.Sprintf("%s/set-password?%s", idp.addr, args)

	m := gomail.NewMessage()
	m.SetAddressHeader("From", idp.mailFrom, idp.name)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Password reset")
	m.SetBody(
		"text/plain",
		fmt.Sprintf("%s:%s\n%s",
			"Here is the link to reset your email password",
			uri,
			"If you did not request it, ignore this message.",
		),
	)
	return m
}
