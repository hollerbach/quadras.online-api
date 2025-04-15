// src/infrastructure/logging/logger.js
const { createLogger, format, transports } = require('winston');
const path = require('path');

// Configuração para diferentes ambientes
const getLogConfiguration = () => {
  const env = process.env.NODE_ENV || 'development';
  const logDir = path.resolve(process.cwd(), 'logs');
  
  // Formato base para todos os ambientes
  const baseFormat = format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.splat()
  );
  
  // Configurações específicas para cada ambiente
  if (env === 'production') {
    return {
      format: format.combine(
        baseFormat,
        format.json()
      ),
      transports: [
        // Log de erros em arquivo separado
        new transports.File({ 
          filename: path.join(logDir, 'error.log'), 
          level: 'error' 
        }),
        // Log de todos os níveis
        new transports.File({ 
          filename: path.join(logDir, 'combined.log')
        })
      ]
    };
  }
  
  // Configuração para desenvolvimento
  return {
    format: format.combine(
      baseFormat,
      format.colorize(),
      format.printf(info => `${info.timestamp} ${info.level}: ${info.message}${info.stack ? '\n' + info.stack : ''}`)
    ),
    transports: [
      // Console para desenvolvimento
      new transports.Console(),
      // Arquivo para desenvolvimento (opcional)
      new transports.File({ 
        filename: path.join(logDir, 'dev.log')
      })
    ]
  };
};

// Criar o logger com a configuração apropriada
const logConfig = getLogConfiguration();
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  ...logConfig,
  // Não sair em exceções não tratadas
  exitOnError: false
});

// Criar pastas de log se não existirem
const fs = require('fs');
const logDir = path.resolve(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

module.exports = logger;