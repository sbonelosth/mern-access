const jwt = require("jsonwebtoken");

function authMiddleware(config) {
  return (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
      const payload = jwt.verify(token, config.jwt.accessSecret);
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

module.exports = authMiddleware;
