// services/index.js
/**
 * Container de Serviços
 * Centraliza a criação e gerenciamento de dependências
 */

const config = require('../config/env.config');

// Componentes base (sem dependências)
const LoggerService = require('./logger');
const logger = LoggerService;

// Serviços da aplicação
const MailService = require('./mail.service');
const TokenService = require('./token.service');
const TwoFactorService = require('./twoFactor.service');
const UserService = require('./user.service');

// Exportação de serviços
module.exports = {
  logger,
  mailService: MailService,
  tokenService: TokenService,
  twoFactorService: TwoFactorService,
  userService: UserService,
  
  /**
   * Método para obter todos os serviços como um objeto único
   * Útil para injeção de dependências
   */
  getServices() {
    return {
      logger: this.logger,
      mailService: this.mailService,
      tokenService: this.tokenService,
      twoFactorService: this.twoFactorService,
      userService: this.userService,
      config
    };
  }
};
