# Go OAuth2 IDP

This projects exposes a simple email/password OAuth2 identity provider.

## Database

Server is running with mongo db. You may need to set environment variable: MONGO_URI.

Otherwise use default mongo uri: `mongodb://localhost:27017`

## Options :

- `-addr localhost:8080` : change default idp server address
- `-name Googal` : change the name of the idp

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

For an extensive documentation, please read source and OAuth2 spec as refered : https://datatracker.ietf.org/doc/html/rfc6749

