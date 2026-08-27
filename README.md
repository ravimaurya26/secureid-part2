# SecureID — IAM Authentication & Registration

A Node.js + Express IAM demo implementing:

- Registration
- Email OTP verification
- SMS OTP verification (simulated)
- MFA enablement
- Login with password verification
- Failed-login attempt tracking
- Temporary account lockout
- Login MFA OTP
- Server-side session authentication
- HttpOnly/SameSite authentication cookie
- `/api/me`
- `/api/logout`
- Short-lived JWT issuance
- JWT protected API
- Responsive HTML/CSS/JavaScript frontend

## 1. Install

```bash
npm install
```

## 2. Run locally

```bash
npm start
```

Open:

```text
http://localhost:3000
```

## 3. Test registration

1. Open `/register.html`.
2. Enter a name, email, phone and password.
3. Submit the form.
4. Look at the terminal running Node.js.
5. Copy the simulated email OTP into the page.
6. After email verification, click **Send SMS OTP**.
7. Copy the simulated SMS OTP from the terminal.
8. Verify it.
9. MFA is now enabled.

## 4. Test login

1. Return to `/`.
2. Enter the same email and password.
3. The backend checks the password with bcrypt.
4. If credentials are valid and MFA is enabled, the backend creates a login OTP challenge.
5. Copy the simulated OTP from the terminal.
6. Enter the OTP.
7. The backend creates the server-side session.
8. The browser receives an HttpOnly authentication cookie.
9. The dashboard calls `/api/me`.

## 5. Test security states

### Wrong password

Submit an incorrect password repeatedly. The backend tracks failures and temporarily locks the account after 5 failed attempts.

### Wrong OTP

Enter an incorrect login OTP. The challenge allows 3 attempts.

### Expired OTP

OTP challenges expire after 5 minutes.

### Single-use OTP

A successfully verified OTP is deleted and cannot be reused.

## 6. JWT flow

Use an API client such as Postman/Thunder Client.

### Issue token

```http
POST /api/token
Content-Type: application/json

{
  "email": "student@example.com",
  "password": "your-password"
}
```

The response contains a short-lived JWT.

### Call protected API

```http
GET /api/protected
Authorization: Bearer YOUR_JWT
```

The server verifies the JWT signature, issuer and expiry before returning protected data.

The frontend does not store JWTs in `localStorage`.

## 7. Vercel

This project includes `vercel.json` and exposes the Express app through `api/index.js`.

After pushing to GitHub:

1. Import the repository into Vercel.
2. Add environment variables:
   - `SESSION_SECRET`
   - `JWT_SECRET`
   - `NODE_ENV=production`
3. Deploy.

### Important demo limitation

The sample uses in-memory `Map` objects for users, OTP challenges and login failures so it can run without a database. Serverless instances can restart, so this is **not production persistence**.

For a production IAM system, replace the Maps with a persistent database/Redis-backed store and use a production-grade session store.

## 8. Security notes

- Passwords are hashed with bcrypt.
- OTPs are generated on the backend.
- OTP values are never returned in API responses.
- Only an HMAC-protected OTP representation is stored.
- OTPs expire and have a maximum attempt count.
- OTPs are single-use.
- Login failures can trigger temporary lockout.
- Session cookie uses HttpOnly and SameSite; Secure is enabled in production.
- JWTs are short-lived and verified server-side.
- JWT is not placed in browser localStorage.

## Assignment mapping

### Registration

`POST /api/register`  
`POST /api/send-email-otp`  
`POST /api/verify-email-otp`  
`POST /api/send-sms-otp`  
`POST /api/verify-sms-otp`

### Login

`POST /api/login`  
`POST /api/verify-login-otp`

### Session

`GET /api/me`  
`POST /api/logout`

### JWT

`POST /api/token`  
`GET /api/protected`
