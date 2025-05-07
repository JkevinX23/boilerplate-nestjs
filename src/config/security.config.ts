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
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
  },
  cookie: {
    secret: process.env.COOKIE_SECRET || 'cookie_secret_key',
  },
}));
