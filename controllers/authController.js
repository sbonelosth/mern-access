const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ms = require("ms");
const crypto = require("crypto");
const generateOTP = require("../lib/otp");
const { signTokens } = require("../lib/jwt");

function authController(config) {
  const refreshExpiryMs = ms(`${config.jwt.refreshExpiry}`);
  let User = config.User; // Mongoose user model

  // --- SIGNUP ---
  const signup = async (req, res) => {
    try {
      const { email, username, password, role, ...additionalFields } = req.body;

      if (!email || !username || !password) {
        return res
          .status(400)
          .json({ success: false, error: "Missing required fields" });
      }
      if (await User.findOne({ email })) {
        return res
          .status(409)
          .json({ success: false, error: "Email already in use" });
      }
      if (await User.findOne({ username })) {
        return res
          .status(409)
          .json({ success: false, error: "Username already taken" });
      }

      const hashedPwd = await bcrypt.hash(password, 10);
      const otp = generateOTP();
      const otpExpiry = config.otpExpiry
        ? Date.now() + ms(`${config.otpExpiry}`)
        : null;

      // Get User model schema paths to validate additional fields
      const userSchemaPaths = User.schema.paths;
      const validAdditionalFields = {};

      // Filter only fields that exist in the User schema
      Object.keys(additionalFields).forEach((field) => {
        if (
          userSchemaPaths[field] &&
          !["email", "username", "password", "role"].includes(field)
        ) {
          validAdditionalFields[field] = additionalFields[field];
        }
      });

      const userData = {
        email,
        username,
        password: hashedPwd,
        role,
        otp,
        otpExpiry,
        ...validAdditionalFields,
      };

      const newUser = await User.create(userData);

      await config.sendEmail({
        to: newUser.email,
        subject: config.email?.subject || "Email Verification Code",
        html: config.email?.body
          ? config.email.body({
              username: newUser.username,
              otp,
              otpExpiry: config.otpExpiry,
            })
          : `<p>Hello ${
              newUser.username
            }, your verification code is <b>${otp}</b>${
              otpExpiry && " and it's valid for " + config.otpExpiry
            }.</p>`,
      });

      // Issue initial tokens
      const { accessToken, refreshToken } = signTokens(
        newUser.username,
        config
      );
      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";
      const tokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

      newUser.refreshTokens.push({
        tokenHash,
        userAgent,
        ip,
        expiresAt: new Date(Date.now() + refreshExpiryMs),
      });

      await newUser.save();

      return res.status(200).json({
        success: true,
        user: config.mapUserData(newUser),
        accessToken,
        message: "Signup successful. Verification code sent.",
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };

  // --- VERIFY ---
  const verify = async (req, res) => {
    const { id, otp } = req.body;
    console.log("Verify called with:", req.body);
    const isEmail = id.includes("@");
    try {
      const user = await User.findOne(
        isEmail ? { email: id } : { username: id }
      );

      if (!user)
        return res
          .status(404)
          .json({ success: false, error: "User not found" });

      if (!otp) {
        const newOtp = generateOTP();
        user.otp = newOtp;
        user.otpExpiry = config.otpExpiry
          ? Date.now() + ms(`${config.otpExpiry}`)
          : null;
        await user.save();

        await config.sendEmail({
          to: user.email,
          subject: config.email?.subject || "Email Verification Code",
          html: config.email?.body
            ? config.email.body({
                username: user.username,
                otp: newOtp,
                otpExpiry: config.otpExpiry,
              })
            : `<p>Hello ${
                user.username
              }, your verification code is <b>${newOtp}</b>${
                user.otpExpiry && " and it's valid for " + config.otpExpiry
              }.</p>>`,
        });

        return res.status(200).json({
          user,
          success: true,
          isOtpSent: true,
          message: "New verification code sent",
        });
      }

      if (user.otp !== otp) {
        return res.status(401).json({ success: false, error: "Invalid code" });
      }

      if (user.otpExpiry && user.otpExpiry < Date.now()) {
        return res
          .status(401)
          .json({ success: false, error: "Code expired, request a new one" });
      }

      user.isEmailVerified = true;
      user.otp = undefined;

      const { accessToken, refreshToken } = signTokens(user.username, config);
      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";
      const tokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

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
        user: config.mapUserData(user),
        accessToken,
        message: "Account verified",
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };

  // --- RESET PASSWORD ---
  const reset = async (req, res) => {
    const { id, otp, newPassword } = req.body;
    const isEmail = id.includes("@");
    if (!id) {
      return res
        .status(400)
        .json({ success: false, error: "Missing required fields" });
    }

    try {
      const user = await User.findOne(
        isEmail ? { email: id } : { username: id }
      );
      if (!user)
        return res
          .status(404)
          .json({ success: false, error: "User not found" });

      if (!otp || !newPassword) {
        const newOtp = generateOTP();
        user.otp = newOtp;
        user.otpExpiry = config.otpExpiry
          ? Date.now() + ms(`${config.otpExpiry}`)
          : null;
        await user.save();

        await config.sendEmail({
          to: user.email,
          subject: "Password Reset Code",
          html: `<p>Hello ${
            user.username
          }, your password reset code is <b>${newOtp}</b>${
            user.otpExpiry && " and it's valid for " + config.otpExpiry
          }.</p>>`,
        });

        return res.status(200).json({
          success: true,
          isOtpSent: true,
          message: "Password reset code sent",
        });
      }

      if (user.otp !== otp) {
        return res.status(401).json({ success: false, error: "Invalid code" });
      }

      if (user.otpExpiry && user.otpExpiry < Date.now()) {
        return res
          .status(401)
          .json({ success: false, error: "Code expired, request a new one" });
      }

      user.password = await bcrypt.hash(newPassword, 10);
      await user.save();
      return res
        .status(200)
        .json({ success: true, message: "Password reset successful" });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  };

  // --- LOGIN ---
  const login = async (req, res) => {
    const { id, password } = req.body;
    const query = (id || "").includes("@") ? { email: id } : { username: id };

    try {
      const user = await User.findOne(query);
      if (!user)
        return res
          .status(401)
          .json({ success: false, error: "Invalid credentials" });

      const match = await bcrypt.compare(password || "", user.password);
      if (!match)
        return res
          .status(401)
          .json({ success: false, error: "Invalid credentials" });
      if (!user.isEmailVerified)
        return res
          .status(403)
          .json({ success: false, error: "Email not verified" });

      const { accessToken, refreshToken } = signTokens(user.username, config);

      const userAgent = req.headers["user-agent"] || "unknown";
      const ip = req.ip || req.connection.remoteAddress || "unknown";

      // Hash refresh for DB storage
      const tokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

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
        user: config.mapUserData(user),
        accessToken,
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
      return res
        .status(401)
        .json({ success: false, error: "Authorization header required" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res
        .status(401)
        .json({ success: false, error: "Access token required" });
    }

    try {
      const payload = jwt.verify(token, config.jwt.accessSecret);
      const user = await User.findOne({ username: payload.username });
      if (!user)
        return res
          .status(404)
          .json({ success: false, error: "User not found" });

      // Access still valid → extend it
      const { accessToken } = signTokens(user.username, config);

      return res.status(200).json({
        success: true,
        user: config.mapUserData(user),
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
    if (!username)
      return res
        .status(400)
        .json({ success: false, error: "Username required" });

    const user = await User.findOne({ username });
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    // Clear all refresh tokens
    user.refreshTokens = [];
    await user.save();

    return res
      .status(200)
      .json({ success: true, message: "Logged out from all devices" });
  };

  return { signup, verify, login, access, reset, logout };
}

module.exports = authController;
