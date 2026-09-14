// SECURE CONFIGURATION — mirrors the vulnerable file structure so the
// diff between the two is the point of comparison in the report.

module.exports = {
  secret: process.env.JWT_SECURE_SECRET, // 64-byte random value from .env

  signOptions: {
    algorithm: 'HS256', // explicitly pinned, not left to caller/default
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE
  },

  verifyOptions: {
    algorithms: ['HS256'], // allowlist of exactly one algorithm
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE
    // expiresIn is enforced automatically by jsonwebtoken during verify
    // based on the token's own exp claim — we do NOT need to (and should
    // not) trust a client-supplied expiry.
  }
};