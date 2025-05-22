// src/infrastructure/database/mysql/sequelize-config.js
const config = require('../../config');
const { Sequelize } = require('sequelize');
const logger = require('../../logging/logger');

// Configurações para diferentes ambientes
module.exports = {
  development: {
    ...config.db.mysql,
    logging: (msg) => logger.debug(msg)
  },
  test: {
    ...config.db.mysql,
    database: config.db.mysql.database + '_test',
    logging: false
  },
  production: {
    ...config.db.mysql,
    logging: false
  }
};