const jwt = require("jsonwebtoken");

function signTokens(username, config) {
  const accessToken = jwt.sign(
    { username },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiry || "3600s" }
  );
  const refreshToken = jwt.sign(
    { username },
    config.jwt.refreshSecret,
    { expiresIn: config.jwt.refreshExpiry || "86400s" }
  );
  return { accessToken, refreshToken };
}

module.exports = { signTokens };