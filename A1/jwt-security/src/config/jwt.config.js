require('dotenv').config();

const mode = process.env.AUTH_MODE === 'secure' ? 'secure' : 'vulnerable';

const config =
  mode === 'secure'
    ? require('../../secure/config/jwt.config')
    : require('../../vulnerable/config/jwt.config');

if (!config.secret) {
  throw new Error(
    `JWT secret is missing for AUTH_MODE=${mode}. Check your .env file.`
  );
}

console.log(`[jwt-security-lab] Running in AUTH_MODE=${mode}`);

module.exports = { mode, ...config };