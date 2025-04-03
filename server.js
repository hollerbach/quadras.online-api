// server.js
require('dotenv').config();
const app = require('./app');
const mongoose = require('mongoose');
const logger = require('./services/logger');
const config = require('./config/env.config');

// Configuração de processo
process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT EXCEPTION! Encerrando...');
  logger.error(err.name, err.message, err.stack);
  process.exit(1);
});

// Variáveis de ambiente e configurações
const { uri, options } = config.db;

// Conexão com o MongoDB
mongoose.connect(uri, options)
  .then(() => {
    logger.info('✅ Conectado ao MongoDB Atlas');
    
    // Iniciar servidor apenas após conexão com o banco de dados
    const server = app.listen(config.app.port, () => {
      logger.info(`🚀 Server rodando na porta ${config.app.port} em modo ${config.app.env}`);
    });

    // Manipulação graciosa de desligamento
    const shutdown = () => {
      logger.info('⚠️ Recebido sinal para desligamento...');
      server.close(() => {
        logger.info('Servidor HTTP fechado.');
        mongoose.connection.close(false, () => {
          logger.info('Conexão com MongoDB fechada.');
          process.exit(0);
        });
        
        // Força o encerramento após 10 segundos
        setTimeout(() => {
          logger.error('Encerramento forçado após timeout!');
          process.exit(1);
        }, 10000);
      });
    };

    // Escutar sinais para desligamento graciosa
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  })
  .catch(err => {
    logger.error('❌ Erro ao conectar ao MongoDB Atlas:', err.message);
    process.exit(1);
  });

// Manipulação de rejeições de promises não tratadas
process.on('unhandledRejection', (err) => {
  logger.error('UNHANDLED REJECTION! Encerrando...');
  logger.error(err.name, err.message, err.stack);
  
  // Falha graciosa em vez de abrupta
  server.close(() => {
    process.exit(1);
  });
});
