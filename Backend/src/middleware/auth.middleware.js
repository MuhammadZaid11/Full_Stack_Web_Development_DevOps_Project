const jwt = require('jsonwebtoken');

/**
 * Express middleware: authenticateToken
 * Verifies Bearer JWT from Authorization header and attaches decoded payload to req.user
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Invalid authorization header format' });
  }

  const token = parts[1];
  const secret = process.env.JWT_SECRET || 'secret';

  try {
    const decoded = jwt.verify(token, secret);
    // attach decoded payload to request for downstream handlers
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

/**
 * Express middleware generator: authorizeRoles(...allowedRoles)
 * Use after authenticateToken. Checks req.user.role (or roles array) against allowedRoles.
 */
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    const user = req.user;
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    const userRoles = Array.isArray(user.role) ? user.role : [user.role];
    const allowed = userRoles.some(r => allowedRoles.includes(r));
    if (!allowed) return res.status(403).json({ message: 'Forbidden' });
    next();
  };
}

/**
 * Optional authentication: if token exists, verify and attach req.user, otherwise continue anonymously.
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return next();

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return next();

  const token = parts[1];
  const secret = process.env.JWT_SECRET || 'secret';
  try {
    req.user = jwt.verify(token, secret);
  } catch (err) {
    // ignore invalid token for optional auth
  }
  next();
}

module.exports = {
  authenticateToken,
  authorizeRoles,
  optionalAuth,
};
