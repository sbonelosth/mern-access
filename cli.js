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
const User = require("./models/User");

module.exports = {
  User,
  jwt: {
    accessSecret: process.env.ACCESS_SECRET || "${accessSecret}",
    refreshSecret: process.env.REFRESH_SECRET || "${refreshSecret}",
    accessExpiry: process.env.ACCESS_EXPIRY || "1h",
    refreshExpiry: process.env.REFRESH_EXPIRY || "1d"
  },
  email: {
    subject: "Email Verification Code",
    body: ({ username, otp, otpExpiry }) => \`<p>Hello \${username}, your code is <b>\${otp}</b>\${otpExpiry && " and it's valid for " + otpExpiry}.</p>\`
  },
  // Optional OTP expiry time
  otpExpiry: "1h", // e.g. "10m", "1h", "1d" - set to null to disable expiry
  // Optional email sending function if you want to log or customize email sending
  async sendEmail({ to, subject, html }) {
    console.log("EMAIL SENT:", to, subject, html);
  },
  // Optional function to map user data returned in API responses (e.g. to remove sensitive fields)
  mapUserData: (user) => ({
    username: user.username,
    email: user.email,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    otpExpiry: user.otpExpiry,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
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
  role: { type: String, default: "user" },
  isEmailVerified: { type: Boolean, default: false },
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
const cors = require("cors");
const mongoose = require("mongoose");
const { initMernAccess } = require("mern-access");
const config = require("./auth.config");

config.sendEmail = async ({ to, subject, html }) {
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

    const { router, protect } = initMernAccess(config);

    const app = express();
    app.use(express.json());
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
const cors = require("cors");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const { initMernAccess } = require("mern-access");
const config = require("./auth.config");
const User = require("./models/User");

// Configure transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Override sendEmail inside config
config.sendEmail = async ({ to, subject, html }) => {
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html
  });
};

// Attach User model too
config.User = User;

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    const { router, protect } = initMernAccess(config);

    const app = express();
    app.use(express.json());
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

# Email (SMTP) settings
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
EMAIL_FROM="Your App <no-reply@yourapp.com>"
`;

// --- Dependencies ---
async function ensurePackageJson(cwd) {
  const pkgPath = path.join(cwd, "package.json");
  if (!fs.existsSync(pkgPath)) {
    ok("📦 No package.json found, running npm init -y...");
    execSync("npm init -y", { cwd, stdio: "inherit" });
  }
}

async function installBaseDeps(cwd, withMailer) {
  try {
    const useYarn = fs.existsSync(path.join(cwd, "yarn.lock"));
    const deps = ["express", "mongoose", "cors", "dotenv", "nodemon", "mern-access"];
    if (withMailer) deps.push("nodemailer");

    const cmd = useYarn
      ? `yarn add ${deps.filter(d => d !== "nodemon").join(" ")} && yarn add -D nodemon`
      : `npm install ${deps.filter(d => d !== "nodemon").join(" ")} && npm install -D nodemon`;

    ok(`📦 Installing dependencies with ${useYarn ? "yarn" : "npm"}...`);
    execSync(cmd, { cwd, stdio: "inherit" });
    ok("✅ Dependencies installed");
  } catch (e) {
    warn("⚠️ Failed to auto-install dependencies. Please run manually.");
  }
}

async function addDevScript(cwd) {
  const pkgPath = path.join(cwd, "package.json");
  if (!fs.existsSync(pkgPath)) {
    warn("⚠️ No package.json found. Run `npm init -y` first.");
    return;
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  pkg.scripts = pkg.scripts || {};
  pkg.scripts.start = "node index.js";
  pkg.scripts.dev = "nodemon index.js";

  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  ok("✅ Added `npm run dev` script to package.json");
}

// --- Commands ---
async function cmdInit(argv) {
  const cwd = process.cwd();
  const withMailer = argv.includes("--with-nodemailer");
  const accessSecret = crypto.randomBytes(64).toString("hex");
  const refreshSecret = crypto.randomBytes(64).toString("hex");

  await ensurePackageJson(cwd);

  const files = [
    {
      path: path.join(cwd, "auth.config.js"),
      content: tmplAuthConfig({ accessSecret, refreshSecret })
    },
    { path: path.join(cwd, "models", "User.js"), content: tmplUserModel },
    {
      path: path.join(cwd, "index.js"),
      content: withMailer ? tmplUsageSampleNodemailer : tmplUsageSampleConsole
    },
    {
      path: path.join(cwd, ".gitignore"),
      content: `node_modules\n.env\n`
    }
  ];

  if (withMailer) {
    files.push({
      path: path.join(cwd, ".env"),
      content: tmplEnvSample({ accessSecret, refreshSecret })
    });
  }

  log("🔧 Initializing mern-access scaffolding...");
  for (const f of files) {
    await writeFileSafe(f.path, f.content);
  }

  await installBaseDeps(cwd, withMailer);
  await addDevScript(cwd);

  log("\n✅ Done.");
  if (withMailer) log("📧 Nodemailer setup included. Check and replace .env values.");
  log("👉 Next step:");
  log("   1. npm run dev          (or yarn dev)");
}


function showHelp() {
  console.log(`
  mern-access CLI

  Usage:
    npx mern-access init                   Scaffold files
    npx mern-access init --with-nodemailer Include nodemailer + .env.sample
    npx mern-access help                   Show this help
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