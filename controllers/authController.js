const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ms = require("ms");
const crypto = require("crypto");
const generateOTP = require("../lib/otp");
const { signTokens } = require("../lib/jwt");

function authController(config, User, sendEmail, mapUserData) {
  if (typeof mapUserData !== "function") {
    mapUserData = (user) => ({
      username: user.username,
      email: user.email,
      verified: user.verified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  }

  const refreshExpiryMs = ms(`${config.jwt.refreshExpiry}`);

  // --- SIGNUP ---
  const signup = async (req, res) => {
    const { email, username, password } = req.body;
    try {
      if (!email || !username || !password) {
        return res.status(400).json({ success: false, error: "Missing required fields" });
      }
      if (await User.findOne({ email })) {
        return res.status(409).json({ success: false, error: "Email already in use" });
      }
      if (await User.findOne({ username })) {
        return res.status(409).json({ success: false, error: "Username already taken" });
      }

      const hashedPwd = await bcrypt.hash(password, 10);
      const otp = generateOTP();

      const newUser = await User.create({
        email,
        username,
        password: hashedPwd,
        joinDate: new Date(),
        verified: false,
        otp,
        refreshTokens: [], // initialize empty
      });

      if (typeof sendEmail === "function") {
        // developer provided their own mailer
        await sendEmail({
          to: newUser.email,
          subject: config.email?.subject || "Verify your account",
          html: config.email?.body
            ? config.email.body({ username: newUser.username, otp })
            : `<p>Hello ${newUser.username}, your verification code is <b>${otp}</b></p>`,
        });
      } else {
        // fallback: log to console so devs can still test OTP flows without mail setup
        console.log("📧 [DEV MODE] Email not sent (no sendEmail provided):", {
          to: newUser.email,
          subject: config.email?.subject || "Verify your account",
          html: config.email?.body
            ? config.email.body({ username: newUser.username, otp })
            : `<p>Hello ${newUser.username}, your verification code is <b>${otp}</b></p>`,
        });
      }


      // Issue initial tokens
      const { accessToken, refreshToken } = signTokens(newUser.username, config);
      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";
      const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

      newUser.refreshTokens.push({
        tokenHash,
        userAgent,
        ip,
        expiresAt: new Date(Date.now() + refreshExpiryMs),
      });

      await newUser.save();

      return res.status(200).json({
        success: true,
        user: mapUserData(newUser),
        accessToken,
        refreshToken,
        message: "Signup successful. Verification code sent.",
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };


  // --- VERIFY ---
  const verify = async (req, res) => {
    const { email, otp } = req.body;
    const isEmail = email.includes('@');
    try {
      const user = await User.findOne(isEmail ? { email } : { username: email });

      if (!user) return res.status(404).json({ success: false, error: "User not found" });

      if (!otp) {
        const newOtp = generateOTP();
        user.otp = newOtp;
        await user.save();

        if (typeof sendEmail === "function") {
          // developer provided their own mailer
          await sendEmail({
            to: user.email,
            subject: config.email?.subject || "Verify your account",
            html: config.email?.body
              ? config.email.body({ username: user.username, otp: newOtp })
              : `<p>Hello ${user.username}, your verification code is <b>${newOtp}</b></p>`,
          });
        } else {
          // fallback: log to console so devs can still test OTP flows without mail setup
          console.log("📧 [DEV MODE] Email not sent (no sendEmail provided):", {
            to: user.email,
            subject: config.email?.subject || "Verify your account",
            html: config.email?.body
              ? config.email.body({ username: user.username, otp: newOtp })
              : `<p>Hello ${user.username}, your verification code is <b>${newOtp}</b></p>`,
          });
        }

        return res
          .status(200)
          .json({ user, success: true, sent: true, message: "New verification code sent" });
      }

      if (user.otp !== otp) {
        return res.status(401).json({ success: false, error: "Invalid code" });
      }

      user.verified = true;
      user.otp = undefined;

      const { accessToken, refreshToken } = signTokens(user.username, config);
      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";
      const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

      // Replace any existing refresh for this device
      user.refreshTokens = user.refreshTokens.filter(
        (rt) => !(rt.userAgent === userAgent && rt.ip === ip)
      );
      user.refreshTokens.push({
        tokenHash,
        userAgent,
        ip,
        expiresAt: new Date(Date.now() + refreshExpiryMs),
      });

      await user.save();

      return res.status(200).json({
        success: true,
        user: mapUserData(user),
        accessToken,
        message: "Account verified",
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };


  // --- LOGIN ---
  const login = async (req, res) => {
    const { identifier, password } = req.body;
    const query = (identifier || "").includes("@")
      ? { email: identifier }
      : { username: identifier };

    try {
      const user = await User.findOne(query);
      if (!user) return res.status(401).json({ success: false, error: "Invalid credentials" });

      const match = await bcrypt.compare(password || "", user.password);
      if (!match) return res.status(401).json({ success: false, error: "Invalid credentials" });
      if (!user.verified)
        return res.status(403).json({ success: false, error: "Email not verified" });

      const { accessToken, refreshToken } = signTokens(user.username, config);

      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";

      // Hash refresh for DB storage
      const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

      // Check existing entry for this device
      const existing = user.refreshTokens.find(
        (rt) => rt.userAgent === userAgent && rt.ip === ip
      );

      let reuse = false;
      if (existing) {
        try {
          jwt.verify(existing.tokenHash, config.jwt.refreshSecret); // verify hash against secret
          reuse = true;
        } catch {
          // expired → remove old
          user.refreshTokens = user.refreshTokens.filter(
            (rt) => rt.tokenHash !== existing.tokenHash
          );
        }
      }

      if (!reuse) {
        user.refreshTokens.push({
          tokenHash,
          userAgent,
          ip,
          expiresAt: new Date(Date.now() + refreshExpiryMs),
        });
      }

      await user.save();

      return res.status(200).json({
        success: true,
        user: mapUserData(user),
        accessToken,
        refreshToken, // send plaintext back to client
        message: "Login successful",
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };


  // --- ACCESS (session heartbeat / sliding renew) ---
  const access = async (req, res) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ success: false, error: "Authorization header required" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ success: false, error: "Access token required" });
    }

    try {
      const payload = jwt.verify(token, config.jwt.accessSecret);
      const user = await User.findOne({ username: payload.username });
      if (!user) return res.status(404).json({ success: false, error: "User not found" });

      // Access still valid → extend it
      const { accessToken } = signTokens(user.username, config);

      return res.status(200).json({
        success: true,
        user: mapUserData(user),
        accessToken,
        message: "Access token renewed",
      });
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          error: "Access token expired, please login again",
        });
      }

      console.error("Access token verification failed:", err.message);
      return res.status(401).json({ success: false, error: "Invalid token" });
    }
  };

  // --- LOGOUT ALL ---
  const logout = async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, error: "Username required" });

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    // Clear all refresh tokens
    user.refreshTokens = [];
    await user.save();

    return res.status(200).json({ success: true, message: "Logged out from all devices" });
  };


  return { signup, verify, login, access, logout };
}

module.exports = authController;