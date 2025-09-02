#!/usr/bin/env node

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const { execSync } = require("child_process");

// --- Helpers ---
const askYesNo = async (question, def = "n") => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const q = `${question} ${def === "y" ? "[Y/n]" : "[y/N]"} `;
  const answer = await new Promise(res => rl.question(q, res));
  rl.close();
  const a = String(answer || "").trim().toLowerCase();
  if (!a) return def === "y";
  return a === "y" || a === "yes";
};

const exists = async (p) => !!(await fsp.stat(p).catch(() => null));
const ensureDir = async (dir) => fsp.mkdir(dir, { recursive: true });

const log = (msg) => console.log(msg);
const ok = (msg) => console.log(`\x1b[32m${msg}\x1b[0m`);
const warn = (msg) => console.log(`\x1b[33m${msg}\x1b[0m`);
const err = (msg) => console.log(`\x1b[31m${msg}\x1b[0m`);

const writeFileSafe = async (filePath, content, { force = false } = {}) => {
  if (await exists(filePath) && !force) {
    const overwrite = await askYesNo(`⚠️  ${path.relative(process.cwd(), filePath)} exists. Overwrite?`, "n");
    if (!overwrite) {
      warn(`Skipped: ${path.relative(process.cwd(), filePath)}`);
      return false;
    }
  }
  await ensureDir(path.dirname(filePath));
  await fsp.writeFile(filePath, content, "utf8");
  ok(`Created: ${path.relative(process.cwd(), filePath)}`);
  return true;
};

// --- Templates ---
const tmplAuthConfig = ({ accessSecret, refreshSecret }) => `
require("dotenv").config();

module.exports = {
  jwt: {
    accessSecret: process.env.ACCESS_SECRET || "${accessSecret}",
    refreshSecret: process.env.REFRESH_SECRET || "${refreshSecret}",
    accessExpiry: process.env.ACCESS_EXPIRY || "15m",
    refreshExpiry: process.env.REFRESH_EXPIRY || "1d"
  },
  cookies: {
    enabled: false,
    name: "rt",
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/auth/refresh",
    maxAgeMs: 7 * 24 * 60 * 60 * 1000
  },
  email: {
    subject: "Verify your account",
    body: ({ username, otp }) => \`<p>Hello \${username}, your code is <b>\${otp}</b>.</p>\`
  },
  mapUserData: (user) => ({
    username: user.username,
    email: user.email,
    verified: user.verified
  })
};
`;

const tmplUserModel = `const mongoose = require("mongoose");

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
  verified: { type: Boolean, default: false },
  otp: String,
  otpExpiry: Date,
  refreshTokens: { type: [refreshTokenSchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.models.User || mongoose.model("User", UserSchema);
`;

const tmplUsageSampleConsole = `/**
 * .usage.sample.js
 *
 * Example usage of mern-access without nodemailer.
 * Integrate directly in your server entry point.
 */

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const { initAuth } = require("mern-access");
const config = require("./auth.config");
const User = require("./models/User");

async function sendEmail({ to, subject, html }) {
  console.log("\\n=== EMAIL (simulated) ===");
  console.log("To:", to);
  console.log("Subject:", subject);
  console.log("HTML:", html);
  console.log("==========================\\n");
}

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    const { router, protect } = initAuth(config, sendEmail, User, config.mapUserData);

    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(cors({ origin: true, credentials: true }));

    app.use("/auth", router);

    // Protected example route
    app.get("/me", protect, (req, res) => {
      res.json({ ok: true, user: req.user });
    });

    const PORT = process.env.PORT || 4001;
    app.listen(PORT, () => console.log(\`🚀 Server running on http://localhost:\${PORT}\`));
  } catch (err) {
    console.error("❌ Mongo connection failed:", err.message);
    process.exit(1);
  }
})();
`;

const tmplUsageSampleNodemailer = `/**
 * .usage.sample.js
 *
 * Example usage of mern-access with nodemailer.
 * Make sure to set environment variables in .env.sample
 */

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const { initAuth } = require("mern-access");
const config = require("./auth.config");
const User = require("./models/User");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail({ to, subject, html }) {
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html
  });
}

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    const { router, protect } = initAuth(config, sendEmail, User, config.mapUserData);

    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(cors({ origin: true, credentials: true }));

    app.use("/auth", router);

    // Protected example route
    app.get("/me", protect, (req, res) => {
      res.json({ ok: true, user: req.user });
    });

    const PORT = process.env.PORT || 4001;
    app.listen(PORT, () => console.log(\`🚀 Server running on http://localhost:\${PORT}\`));
  } catch (err) {
    console.error("❌ Mongo connection failed:", err.message);
    process.exit(1);
  }
})();
`;

const tmplEnvSample = ({ accessSecret, refreshSecret }) => `# Environment variables for mern-access + nodemailer
ACCESS_SECRET=${accessSecret}
REFRESH_SECRET=${refreshSecret}
MONGO_URI=mongodb://localhost:27017/yourdb
PORT=4001

# Email sending (nodemailer)
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
EMAIL_FROM="Your App <no-reply@yourapp.com>"
`;

// --- Commands ---
async function installNodemailer(cwd) {
  try {
    const useYarn = fs.existsSync(path.join(cwd, "yarn.lock"));
    const cmd = useYarn ? "yarn add nodemailer" : "npm install nodemailer";
    ok(`📦 Installing nodemailer using ${useYarn ? "yarn" : "npm"}...`);
    execSync(cmd, { stdio: "inherit" });
    ok("✅ nodemailer installed");
  } catch (e) {
    warn("⚠️ Failed to auto-install nodemailer. Please run manually: npm install nodemailer OR yarn add nodemailer");
  }
}

async function cmdInit(argv) {
  const cwd = process.cwd();
  const withMailer = argv.includes("--with-nodemailer");
  const accessSecret = crypto.randomBytes(64).toString("hex");
  const refreshSecret = crypto.randomBytes(64).toString("hex");

  const files = [
    { path: path.join(cwd, "auth.config.js"), content: tmplAuthConfig({ accessSecret, refreshSecret }) },
    { path: path.join(cwd, "models", "User.js"), content: tmplUserModel },
    { path: path.join(cwd, ".usage.sample.js"), content: withMailer ? tmplUsageSampleNodemailer : tmplUsageSampleConsole }
  ];

  if (withMailer) {
    files.push({ path: path.join(cwd, ".env.sample"), content: tmplEnvSample({ accessSecret, refreshSecret }) });
    await installNodemailer(cwd);
  }

  log("🔧 Initializing mern-access scaffolding...");
  for (const f of files) {
    await writeFileSafe(f.path, f.content);
  }

  log("\n✅ Done.");
  if (withMailer) log("📧 Nodemailer setup included. Check .env.sample for variables.");
}

function showHelp() {
  console.log(`
  mern-access CLI

  Usage:
    npx mern-access init             Scaffold auth.config.js, models/User.js, routes/auth.js
    npx mern-access init --with-nodemailer  Same as above but includes nodemailer + .env.sample
    npx mern-access help             Show this help
  `);
}

(async function main() {
  const argv = process.argv.slice(2);

  const cmd = argv[0];
  switch (cmd) {
    case "init":
      await cmdInit(argv);
      break;
    case "help":
    case undefined:
      showHelp();
      break;
    default:
      err(`Unknown command: ${cmd}`);
      showHelp();
      process.exit(1);
  }
})().catch((e) => {
  err(e.stack || e.message || String(e));
  process.exit(1);
});
