const express = require("express");

function authRoutes(ctrl, requireAuth) {
  const router = express.Router();

  // Public
  router.post("/signup", ctrl.signup);
  router.post("/verify", ctrl.verify);
  router.post("/login", ctrl.login);
  router.post("/refresh", ctrl.access);

  // Protected
  router.post("/logout-everywhere", requireAuth, ctrl.logout);

  return router;
}

module.exports = authRoutes;
