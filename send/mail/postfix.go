package mail

import (
	"context"
	"github.com/go-gomail/gomail"
	"log"
	"os"
	"os/exec"
)

type postFixClient struct {
	idp idp
}

func NewPostFixClient(idpAddr, idpName string) *postFixClient {
	idp := idp{
		addr:    idpAddr,
		name:    idpName,
		replyTo: os.Getenv("IDP_REPLY_TO"),
	}
	err := idp.validate()
	if err != nil {
		log.Fatal(err.Error())
	}
	return &postFixClient{idp: idp}
}

func (c *postFixClient) SendResetPasswordToken(ctx context.Context, email, args string) error {
	mail := newResetPasswordEmail(c.idp, email, args)
	return c.send(mail)
}

func (c *postFixClient) send(m *gomail.Message) error {
	cmd := exec.Command("/usr/sbin/sendmail", "-t")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	pw, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	err = cmd.Start()
	if err != nil {
		return err
	}

	var errs [3]error
	_, errs[0] = m.WriteTo(pw)
	errs[1] = pw.Close()
	errs[2] = cmd.Wait()
	for _, err = range errs {
		if err != nil {
			return err
		}
	}
	return err
}
