const authController = require("./controllers/authController");
const authRoutes = require("./routes/authRoutes");
const authMiddleware = require("./middleware/authMiddleware");

/**
 * Initialize MERN Auth
 * @param {Object} config - configuration (jwt secrets, expiries, cookies, email template, map user data function)
 * @param {Function} sendEmail - async ({ to, subject, html }) => void
 * @param {Model} User - required custom Mongoose model / user schema
 * @returns {{ router: import('express').Router, protect: Function, User: any }}
 */
function initAuth(config, sendEmail, User) {
  if (!config?.jwt?.accessSecret || !config?.jwt?.refreshSecret) {
    throw new Error("initAuth: jwt.accessSecret and jwt.refreshSecret are required");
  }

  const mapUserData = config.mapUserData;

  const controller = authController(config, User, sendEmail, mapUserData);
  const protect = authMiddleware(config);
  const router = authRoutes(controller, protect);
  return { router, protect, User };
}

module.exports = { initAuth };
