const authController = require("./controllers/authController");
const authRoutes = require("./routes/authRoutes");
const authMiddleware = require("./middleware/authMiddleware");

function initMernAccess(config) {
  if (!config?.jwt?.accessSecret || !config?.jwt?.refreshSecret) {
    throw new Error("initMernAccess: jwt.accessSecret and jwt.refreshSecret are required");
  }

  // --- Normalize config defaults ---
  if (typeof config.mapUserData !== "function") {
    config.mapUserData = (user) => ({
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      otpExpiry: user.otpExpiry,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  }

  if (typeof config.sendEmail !== "function") {
    config.sendEmail = async ({ to, subject, html }) => {
      console.log("📧 [DEV MODE] Email not sent (no sendEmail provided):", { to, subject, html });
    };
  }

  if (!config.email) config.email = {};
  if (typeof config.email.body !== "function") {
    config.email.body = ({ username, otp, otpExpiry }) =>
      `<p>Hello ${username}, your code is <b>${otp}</b>${
        otpExpiry ? " and valid for " + otpExpiry : ""
      }.</p>`;
  }
  if (!config.email.subject) {
    config.email.subject = "Email Verification Code";
  }

  // --- Init core ---
  const controller = authController(config);
  const protect = authMiddleware(config);
  const router = authRoutes(controller, protect);

  return { router, protect };
}

module.exports = { initMernAccess };