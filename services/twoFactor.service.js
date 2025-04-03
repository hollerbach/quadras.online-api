// services/twoFactor.service.js
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const logger = require('./logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');

class TwoFactorService {
  /**
   * Gera um segredo para autenticação de dois fatores
   * @param {string} userEmail - Email do usuário para identificação no app
   * @param {string} appName - Nome da aplicação que aparece no app
   * @returns {Object} Objeto contendo informações do segredo
   */
  generateSecret(userEmail, appName = 'Mercearia Digital') {
    try {
      return speakeasy.generateSecret({
        name: `${appName} (${userEmail})`,
        length: 20
      });
    } catch (error) {
      logger.error(`Erro ao gerar segredo 2FA: ${error.message}`);
      throw new ApiError(500, 'Erro ao gerar segredo para autenticação de dois fatores');
    }
  }

  /**
   * Verifica o token TOTP fornecido pelo usuário
   * @param {string} secret - Segredo armazenado para o usuário
   * @param {string} token - Token fornecido pelo usuário
   * @param {number} window - Janela de tempo para validação (padrão: 1)
   * @returns {boolean} Verdadeiro se o token for válido
   */
  verifyToken(secret, token, window = 1) {
    try {
      return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window
      });
    } catch (error) {
      logger.error(`Erro ao verificar token 2FA: ${error.message}`);
      throw new ApiError(500, 'Erro ao verificar token de autenticação');
    }
  }

  /**
   * Gera um QR Code para configuração do app TOTP
   * @param {string} otpauthUrl - URL de autenticação TOTP
   * @returns {Promise<string>} QR Code em formato de Data URL
   */
  async generateQRCode(otpauthUrl) {
    try {
      return await qrcode.toDataURL(otpauthUrl);
    } catch (error) {
      logger.error(`Erro ao gerar QR code: ${error.message}`);
      throw new ApiError(500, 'Erro ao gerar QR Code para configuração 2FA');
    }
  }

  /**
   * Gera um token TOTP de recuperação
   * @param {string} secret - Segredo do usuário
   * @returns {string} Token TOTP válido no momento
   */
  generateBackupToken(secret) {
    try {
      return speakeasy.totp({
        secret,
        encoding: 'base32'
      });
    } catch (error) {
      logger.error(`Erro ao gerar token de backup: ${error.message}`);
      throw new ApiError(500, 'Erro ao gerar token de recuperação');
    }
  }

  /**
   * Gera múltiplos códigos de recuperação
   * @param {number} count - Número de códigos a serem gerados
   * @returns {Array<string>} Lista de códigos de recuperação
   */
  generateRecoveryCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      // Código alfanumérico de 10 caracteres
      const code = Array(10)
        .fill(0)
        .map(() => {
          const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
          return chars.charAt(Math.floor(Math.random() * chars.length));
        })
        .join('');

      // Formatação com hífen para melhor legibilidade (ex: ABCDE-FGHIJ)
      codes.push(`${code.slice(0, 5)}-${code.slice(5)}`);
    }
    return codes;
  }
  // No twoFactorService.js, adicionar método para verificar código de recuperação
  /**
   * Verifica se um código de recuperação é válido
   * @param {Array} recoveryCodes - Lista de códigos de recuperação
   * @param {string} code - Código fornecido pelo usuário
   * @returns {Object} Resultado da verificação e índice do código
   */
  verifyRecoveryCode(recoveryCodes, code) {
    const normalizedCode = code.replace(/\s+/g, '').toUpperCase();

    for (let i = 0; i < recoveryCodes.length; i++) {
      const storedCode = recoveryCodes[i].code.replace(/\s+/g, '').toUpperCase();
      if (storedCode === normalizedCode && !recoveryCodes[i].used) {
        return { valid: true, index: i };
      }
    }

    return { valid: false, index: -1 };
  }
}

module.exports = new TwoFactorService();
