# FREEDOM CHAT

A secure, private, and anonymous chat platform for the Tor network.

## 🌐 **Live Website**

**Access FREEDOM CHAT here:**  
`after the launch.`

*Requires Tor Browser to access*

## Features
- Private by design - no email required
- End-to-end encrypted via Tor
- Messages auto-delete after 24 hours
- 16-word recovery phrase (no email resets)
- Optional device fingerprinting with consent
- Role-based chat system
- Private messaging with offline delivery

## Security
- Bcrypt hashed passwords and PINs
- Rate limiting on all endpoints
- CSRF protection
- XSS sanitization
- Account lockout after 2 failed attempts
- Security headers (CSP, HSTS, etc.)

## Installation (for developers)
1. Clone repository
2. Run `npm install`
3. Create `.env` file with session secret
4. Run `node server.js`

## License
MIT
