const rateLimit = require('express-rate-limit');

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // 10 tentativas por IP
  message: 'Muitas tentativas de login. Tente novamente mais tarde.',
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = loginRateLimiter;
