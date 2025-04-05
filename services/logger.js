const { createLogger, format, transports } = require('winston');

const logger = createLogger({
  format: format.combine(
    format.timestamp(),
    format.printf(info => `${info.timestamp} [${info.level.toUpperCase()}] - ${info.message}`)
  ),
  transports: [new transports.File({ filename: 'logs/auth.log' })]
});

module.exports = logger;
