# mern-access

```mern-access``` is a plug-and-play authentication and authorization solution for MERN applications. It provides a ready-made set of Express routes, middleware, and utilities for handling user sign-up, login, email verification via OTP, and session management — all wired up with a MongoDB + Mongoose connection.

---

## 1. Quick Start (Scaffold a New Project)

Run one of the following on an empty project folder to create a ready-to-use auth setup:

```bash
# Without nodemailer
npx mern-access init

# With nodemailer
npx mern-access init --with-nodemailer
```

This generates the following structure:

```
my-app/
├── models/
│   └── User.js
├── auth.config.js
├── index.js
├── .env
├── package.json
├── node_modules/
└── ...
```

---

## 2. File Samples

### models/User.js
```js
const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, index: true },
  userAgent: String,
  ip: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, index: true }
}, { _id: false });

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true, required: true },
  username: { type: String, unique: true, index: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },
  isEmailVerified: { type: Boolean, default: false },
  otp: String,
  otpExpiry: Date,
  refreshTokens: { type: [refreshTokenSchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.models.User || mongoose.model("User", UserSchema);
```

---

### auth.config.js
```js
require("dotenv").config();
const User = require("./models/User");

module.exports = {
  User,
  jwt: {
    accessSecret: process.env.ACCESS_SECRET,
    refreshSecret: process.env.REFRESH_SECRET,
    accessExpiry: "1h",
    refreshExpiry: "1d"
  },
  email: {
    subject: "Email Verification Code",
    body: ({ username, otp, otpExpiry }) =>
      `<p>Hello ${username}, your code is <b>${otp}</b>${otpExpiry ? " and valid for " + otpExpiry : ""}.</p>`
  },
  otpExpiry: "1h",
  async sendEmail({ to, subject, html }) {
    // Console version (default). If using nodemailer, replace with transporter.sendMail.
    console.log("EMAIL SENT:", to, subject, html);
  },
  mapUserData: (user) => ({
    username: user.username,
    email: user.email,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  })
};
```
---

### Notes

```sendEmail``` can be any async function (nodemailer, external API, or console).

```mapUserData``` controls what user info is exposed in responses.


---

### index.js
```js
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const { initMernAccess } = require("mern-access");
const config = require("./auth.config");

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    const { router, protect } = initMernAccess(config);

    const app = express();
    app.use(express.json());
    app.use(cors({ origin: true, credentials: true }));

    app.use("/auth", router);

    // Example protected route
    app.get("/me", protect, (req, res) => {
      res.json({ ok: true, user: req.user });
    });

    const PORT = process.env.PORT || 4001;
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (err) {
    console.error("❌ [mern-access] connection failed:", err.message);
    process.exit(1);
  }
})();
```

---

### .env
```env
ACCESS_SECRET=your-random-access-secret
REFRESH_SECRET=your-random-refresh-secret
MONGO_URI=mongodb://localhost:27017/yourdb
PORT=4001

# Email (SMTP)
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
EMAIL_FROM="Your App <no-reply@yourapp.com>"
```

---

## 3. Setup

1. Replace values in `.env` with your actual secrets & SMTP config.
2. Run the dev server:

```bash
npm run dev
```

---

## 4. Routes

| Method | Endpoint                  | Description                                        | Expected Data                                                  |
| ------ | ------------------------- | -------------------------------------------------- | -------------------------------------------------------------- |
| POST   | `/auth/signup`            | Create new user and send OTP                       | **body:** `{ email, username, password, role? }`                      |
| POST   | `/auth/verify`            | Send OTP / resend OTP / verify OTP | **body:** `{ email }` (send/resend), `{ email, otp }` (verify) |
| POST   | `/auth/login`             | Login with email/username + password               | **body:** `{ emailOrUsername, password }`                      |
| POST   | `/auth/access`            | Refresh access token using refresh cookie          | **headers["authorization"]:** `Bearer token`                   |
| POST   | `/auth/logout-everywhere` | Logout from all sessions                           | **body:** `{ username }`                   |
|

---

## curl Examples

Signup:
```bash
curl -X POST http://localhost:4001/auth/signup -H "Content-Type: application/json" -d '{"email":"alice@example.com","username":"alice","password":"Secret123"}'
```

Verify:
```bash
curl -X POST http://localhost:4001/auth/verify -H "Content-Type: application/json" -d '{"email":"alice@example.com","otp":"123456"}'
```

Login:
```bash
curl -X POST http://localhost:4001/auth/login -H "Content-Type: application/json" -d '{"id":"alice","password":"Secret123"}'
```

---

## 5. Using in an Existing Project

Install the package:

```bash
npm install mern-access
```

Add config:

```js
const { initMernAccess } = require("mern-access");
const config = require("./auth.config");

// Connect to MongoDB before initializing mern-access
const { router, protect } = initMernAccess(config);
app.use("/auth", router);
```

Protect routes:

```js
app.get("/me", protect, (req, res) => {
  res.json({ user: req.user });
});
```

---

## License

MIT License

Copyright (c) 2025
