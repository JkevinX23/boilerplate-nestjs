import { registerAs } from '@nestjs/config';

export default registerAs('security', () => ({
  jwt: {
    secret: process.env.JWT_SECRET || 'hard_to_guess_secret_key',
    expiresIn: parseInt(process.env.JWT_EXPIRATION || '3600', 10),
  },
  throttle: {
    ttl: parseInt(process.env.THROTTLE_TTL || '60', 10),
    limit: parseInt(process.env.THROTTLE_LIMIT || '10', 10),
  },
  failedLoginAttempts: {
    maxAttempts: parseInt(process.env.FAILED_LOGIN_MAX_ATTEMPTS || '5', 10),
    attemptWindowSeconds: parseInt(
      process.env.FAILED_LOGIN_WINDOW_SECONDS || '300',
      10,
    ),
    blockDurationSeconds: parseInt(
      process.env.FAILED_LOGIN_BLOCK_SECONDS || '900',
      10,
    ),
  },
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
  },
  cookie: {
    secret: process.env.COOKIE_SECRET || 'cookie_secret_key',
  },
}));
