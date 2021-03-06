# Go OAuth2 IDP

This projects exposes a simple email/password OAuth2 identity provider.

## Endpoints

- `/auth` : generate authorization code
- `/client` : register a new oauth2 client consumer
- `/token` : get an access token from an authorization code
- `/user` : get user identity

The consent is **implicit** after user logged in. User identity has the following properties :
- uid: a unique identifier
- firstName: user first name
- lastName: user last name
- email: user email

For an extensive documentation, please read source and OAuth2 spec as referred : https://datatracker.ietf.org/doc/html/rfc6749

## Database

Server is running with mongo db. You may need to set environment variable: MONGO_URI.

Otherwise use default mongo uri: `mongodb://localhost:27017`

## Mailer

A mailer is there to send emails to users that forgot their password.

By default, Postfix is used to send emails, but you can set it to use an SMTP external server.

If you use SMTP, you **need** this environment variables set :
- IDP_SMTP_USERNAME
- IDP_SMTP_PASSWORD
- IDP_SMTP_HOST


## Options :

- `-port 8080`: set idp port
- `-name Googal`: set idp name
- `-addr http://localhost:8080`: set idp url
- `-mailer postfix`: set default mailer. Other options : `smtp`.
- `-mailFrom no-reply@idp.org`: set default reply address used in header. For instance in reset password emails.