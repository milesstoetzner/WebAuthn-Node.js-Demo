#  On the (In-) Security of the W3C WebAuthentication Draft: A Description and Security Analysis

This website has been implemented as part of my bachelor thesis in order to analyse the W3C [Web Authentication](https://www.w3.org/TR/webauthn/) Draft. For more information see my [bachelor thesis](/public/publication.pdf).

## Interface
The table below provides an overview of the available routes and functionalities. POST requests are using CSRF protection.

| ROUTE | METHOD | DESCRIPTION |
| --- | --- | --- |
| /   | GET | Display landing page where a user can register or authenticate |
| /profile  | GET | Display user's profile (including the functionality to register an additional device) |
| /user  | GET | Display user's registered information |
| /register  | POST | First part of a registration: check if name is available, provide options (including a User Handle and a Challenge) and return a script calling the WebAuthn API |
| /register/callback  | POST | Second part of a registration: validate and register user's public key |
| /authenticate | POST | First part of an authentication: find user by name, provides options (including the user's Credential ID and a Challenge) and return a script calling the WebAuthn API |
| /authenticate/callback | POST | Second part of an authentication: validate received Assertion Signature and authenticate user |
| /logout  | POST | Logs out user|
| /help | GET | Display help page |

## Dependencies
The system has been developed using Windows 10 Home and a Firefox Softtoken instead of a FIDO U2F Security Token. There are the following dependencies:

- Mozilla Firefox Version 60.0.1
- FIDO U2F Security Token
- Node.js v8.9.4
- ECMAScript 6

## Firefox Softtoken
Instead of a FIDO U2F Security Token the build-in Firefox Softtoken can be used. Therefore do the following:
- open `about:config` in your browser
- enable `security.webauth.webauthn`
- enable `security.webauth.webauthn_enable_softtoken`
- disable `security.webauth.webauthn_enable_usbtoken`

## Deployment
To run the server use the command `npm install && node ./bin/www`. 

On the first start the newest version of MongoDB will be downloaded and installed.

The server uses the origin `https://ascensus.com`. Make sure that `https://ascensus.com` resolves to your localhost. On windows you can achieve this by adding `127.0.0.1			ascensus.com` in the file `C:/Windows/System32/drivers/etc/hosts`.
  
## Author
Miles Stötzner  
miles@stoetzner.de  
University of Stuttgart