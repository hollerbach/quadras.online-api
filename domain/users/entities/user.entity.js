// src/domain/users/entities/user.entity.js

/**
 * Classe de entidade User
 * Representa um usuário do sistema com suas regras de negócio
 */
class User {
    constructor({
      id,
      email,
      password,
      role = 'user',
      verified = false,
      active = true,
      twoFactorEnabled = false,
      twoFactorSecret = null,
      recoveryCodes = [],
      oauth = {},
      name = null,
      surname = null,
      createdAt = new Date(),
      updatedAt = new Date(),
      lastLogin = null,
      loginAttempts = 0,
      lockUntil = null
    }) {
      this.id = id;
      this.email = email;
      this.password = password;
      this.role = role;
      this.verified = verified;
      this.active = active;
      this.twoFactorEnabled = twoFactorEnabled;
      this.twoFactorSecret = twoFactorSecret;
      this.recoveryCodes = recoveryCodes;
      this.oauth = oauth;
      this.name = name;
      this.surname = surname;
      this.createdAt = createdAt;
      this.updatedAt = updatedAt;
      this.lastLogin = lastLogin;
      this.loginAttempts = loginAttempts;
      this.lockUntil = lockUntil;
    }
  
    /**
     * Verifica se a conta está bloqueada
     * @returns {boolean} Verdadeiro se a conta estiver bloqueada
     */
    isLocked() {
      return !!(this.lockUntil && this.lockUntil > new Date());
    }
  
    /**
     * Incrementa o contador de tentativas de login falhas
     * @returns {User} Instância atualizada do usuário
     */
    incrementLoginAttempts() {
      // Se existe um bloqueio, mas já expirou
      if (this.lockUntil && this.lockUntil < new Date()) {
        this.loginAttempts = 1;
        this.lockUntil = null;
      } else {
        // Incrementar contador
        this.loginAttempts += 1;
  
        // Bloquear a conta após 5 tentativas falhas
        if (this.loginAttempts >= 5 && !this.isLocked()) {
          // Bloquear por 1 hora
          this.lockUntil = new Date(Date.now() + 60 * 60 * 1000);
        }
      }
  
      return this;
    }
  
    /**
     * Reseta o contador de tentativas de login
     * @returns {User} Instância atualizada do usuário
     */
    resetLoginAttempts() {
      this.loginAttempts = 0;
      this.lockUntil = null;
      this.lastLogin = new Date();
      return this;
    }
  
    /**
     * Atualiza a data de último login
     * @returns {User} Instância atualizada do usuário
     */
    updateLastLogin() {
      this.lastLogin = new Date();
      return this;
    }
  
    /**
     * Verifica se um código de recuperação é válido
     * @param {string} code Código de recuperação fornecido
     * @returns {boolean} Verdadeiro se o código for válido
     */
    validateRecoveryCode(code) {
      const recoveryCodeIndex = this.recoveryCodes.findIndex(
        c => c.code === code && !c.used
      );
  
      if (recoveryCodeIndex >= 0) {
        this.recoveryCodes[recoveryCodeIndex].used = true;
        return true;
      }
  
      return false;
    }
  
    /**
     * Define ou substitui os códigos de recuperação
     * @param {string[]} codes Novos códigos de recuperação
     * @returns {User} Instância atualizada do usuário
     */
    setRecoveryCodes(codes) {
      this.recoveryCodes = codes.map(code => ({
        code,
        used: false
      }));
  
      return this;
    }
  
    /**
     * Desativa a conta do usuário
     * @returns {User} Instância atualizada do usuário
     */
    deactivate() {
      this.active = false;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Ativa a conta do usuário
     * @returns {User} Instância atualizada do usuário
     */
    activate() {
      this.active = true;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Atualiza as informações do usuário
     * @param {Object} data Dados a serem atualizados
     * @returns {User} Instância atualizada do usuário
     */
    update(data) {
      const allowedFields = [
        'name',
        'surname',
        'role',
        'verified',
        'active',
        'twoFactorEnabled'
      ];
  
      for (const [key, value] of Object.entries(data)) {
        if (allowedFields.includes(key)) {
          this[key] = value;
        }
      }
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Habilita a autenticação de dois fatores
     * @param {string} secret Segredo para TOTP
     * @returns {User} Instância atualizada do usuário
     */
    enable2FA(secret) {
      this.twoFactorEnabled = true;
      this.twoFactorSecret = secret;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Desabilita a autenticação de dois fatores
     * @returns {User} Instância atualizada do usuário
     */
    disable2FA() {
      this.twoFactorEnabled = false;
      this.twoFactorSecret = null;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Verifica um e-mail
     * @returns {User} Instância atualizada do usuário
     */
    verifyEmail() {
      this.verified = true;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Vincula uma conta OAuth ao usuário
     * @param {string} provider Nome do provedor (google, facebook, etc)
     * @param {Object} profile Dados do perfil OAuth
     * @returns {User} Instância atualizada do usuário
     */
    linkOAuthAccount(provider, profile) {
      if (!this.oauth) {
        this.oauth = {};
      }
  
      this.oauth[provider] = profile;
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Desvincula uma conta OAuth do usuário
     * @param {string} provider Nome do provedor (google, facebook, etc)
     * @returns {User} Instância atualizada do usuário
     */
    unlinkOAuthAccount(provider) {
      if (this.oauth && this.oauth[provider]) {
        delete this.oauth[provider];
        this.updatedAt = new Date();
      }
      return this;
    }
  
    /**
     * Retorna uma versão sanitizada do usuário (sem campos sensíveis)
     * @param {boolean} isAdmin Se o solicitante é admin (para inclusão de campos adicionais)
     * @returns {Object} Objeto do usuário sem campos sensíveis
     */
    toSafeObject(isAdmin = false) {
      const safeUser = {
        id: this.id,
        email: this.email,
        name: this.name,
        surname: this.surname,
        role: this.role,
        verified: this.verified,
        active: this.active,
        twoFactorEnabled: this.twoFactorEnabled,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
        lastLogin: this.lastLogin,
        hasOAuth: !!this.oauth && Object.keys(this.oauth).length > 0
      };
  
      // Campos adicionais para admin
      if (isAdmin) {
        safeUser.loginAttempts = this.loginAttempts;
        safeUser.lockUntil = this.lockUntil;
        safeUser.oauth = this.oauth;
      }
  
      return safeUser;
    }
  }
  
  module.exports = User;