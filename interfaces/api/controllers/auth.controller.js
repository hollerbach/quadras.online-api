// src/interfaces/api/controllers/auth.controller.js
const AuthUseCaseFactory = require('../../../domain/auth/factories/auth-use-case.factory');
const userRepository = require('../../../infrastructure/database/mysql/repositories/user.repository');
const authService = require('../../../infrastructure/security/auth.service');
const tokenService = require('../../../infrastructure/security/token.service');
const twoFactorService = require('../../../infrastructure/security/two-factor.service');
const config = require('../../../infrastructure/config');
const securityConfig = require('../../../infrastructure/security/security.config');
const logger = require('../../../infrastructure/logging/logger');
const { BadRequestError, UnauthorizedError } = require('../../../shared/errors/api-error');

/**
 * Controlador para rotas de autenticação
 * Responsável por orquestrar os casos de uso e transformar seus resultados em respostas HTTP
 * Usa o serviço centralizado de autenticação para verificações
 */
class AuthController {
  /**
   * Registra um novo usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async register(req, res) {
    // Usar caso de uso através da factory para seguir o padrão DI
    const registerUseCase = AuthUseCaseFactory.createRegisterUserUseCase();
    const result = await registerUseCase.execute(req.body, req.ip);

    // Registrar evento de auditoria
    await authService.logAuthEvent('REGISTER', 
      { id: result.user.id, email: result.user.email }, 
      req.ip, 
      { role: req.body.role || 'user' }
    );

    res.status(201).json({
      message: 'Usuário registrado com sucesso. Verifique seu e-mail para ativar a conta.',
      user: result.user
    });
  }

  /**
   * Verifica o e-mail do usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async verifyEmail(req, res) {
    const { token } = req.query;
    
    if (!token) {
      throw new BadRequestError('Token de verificação não fornecido');
    }
    
    const verifyEmailUseCase = AuthUseCaseFactory.createVerifyEmailUseCase();
    const result = await verifyEmailUseCase.execute(token, req.ip);

    res.status(200).json(result);
  }

  /**
   * Autentica um usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async login(req, res) {
    const { email, password } = req.body;
    const ipAddress = req.ip;

    // Usar o serviço centralizado para verificar credenciais
    const user = await authService.verifyCredentials(email, password, ipAddress);

    // Verificar se 2FA está ativado
    if (user.twoFactorEnabled) {
      const tempToken = tokenService.generateTempToken({ 
        id: user.id, 
        email: user.email
      });

      // Registrar evento de autenticação 2FA necessária
      await authService.logAuthEvent('LOGIN_2FA_REQUIRED', user, ipAddress);

      return res.status(206).json({
        message: '2FA necessário',
        tempToken
      });
    }

    // Gerar tokens para usuário autenticado
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    this._setRefreshTokenCookie(res, refreshToken.token);

    // Registrar evento de login bem-sucedido
    await authService.logAuthEvent('LOGIN', user, ipAddress, { 
      user2FA: user.twoFactorEnabled 
    });

    res.status(200).json({
      accessToken,
      user: user.toSafeObject()
    });
  }

  /**
   * Verifica o token 2FA e completa o login
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async verify2FA(req, res) {
    const { token, tempToken } = req.body;
    const ipAddress = req.ip;

    // Verificar token temporário usando o serviço centralizado
    const decoded = await tokenService.verifyAndDecodeToken(tempToken, { 
      require2FAToken: true 
    });

    // Buscar usuário
    const user = await authService.verifyUser(decoded.id, {
      requireVerified: true,
      requireActive: true
    });

    if (!user.twoFactorEnabled) {
      throw new BadRequestError('2FA não está habilitado para este usuário');
    }

    // Verificar o token TOTP
    const verified = twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      // Registrar falha na auditoria
      await authService.logAuthEvent('LOGIN_2FA_FAILED', user, ipAddress);
      
      throw new UnauthorizedError('Código 2FA inválido');
    }

    // Gerar tokens para usuário autenticado com 2FA
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    this._setRefreshTokenCookie(res, refreshToken.token);

    // Registrar evento de autenticação 2FA completada
    await authService.logAuthEvent('LOGIN_2FA_SUCCESS', user, ipAddress);

    res.status(200).json({
      accessToken,
      user: user.toSafeObject()
    });
  }

  /**
   * Autentica com código de recuperação 2FA
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async verify2FARecovery(req, res) {
    const { code, tempToken } = req.body;
    const ipAddress = req.ip;

    // Verificar token temporário usando o serviço centralizado
    const decoded = await tokenService.verifyAndDecodeToken(tempToken, { 
      require2FAToken: true 
    });

    // Buscar usuário
    const user = await authService.verifyUser(decoded.id, {
      requireVerified: true,
      requireActive: true
    });

    if (!user.twoFactorEnabled) {
      throw new BadRequestError('2FA não está habilitado para este usuário');
    }

    // Verificar o código de recuperação
    const recoveryCodeValid = await user.validateRecoveryCode(code);

    if (!recoveryCodeValid) {
      await authService.logAuthEvent('LOGIN_2FA_RECOVERY_FAILED', user, ipAddress);
      throw new UnauthorizedError('Código de recuperação inválido');
    }

    // Salvar mudanças (marcar código como usado)
    await userRepository.save(user);

    // Gerar tokens para usuário autenticado com 2FA
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    this._setRefreshTokenCookie(res, refreshToken.token);

    // Registrar evento de login com código de recuperação
    await authService.logAuthEvent('LOGIN_2FA_RECOVERY_SUCCESS', user, ipAddress);

    res.status(200).json({
      accessToken,
      user: user.toSafeObject(),
      recoveryCodesRemaining: user.recoveryCodes.filter(c => !c.used).length
    });
  }

  /**
   * Configura a autenticação de dois fatores para um usuário
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async setup2FA(req, res) {
    const userId = req.user.id;
    const ipAddress = req.ip;

    // Usar caso de uso para configuração 2FA
    const setup2FAUseCase = AuthUseCaseFactory.createSetup2FAUseCase();
    const result = await setup2FAUseCase.execute(userId, ipAddress);

    // Registrar evento de configuração 2FA
    await authService.logAuthEvent('2FA_SETUP', 
      { id: userId, email: req.user.email }, 
      ipAddress
    );

    res.status(200).json({
      qrCode: result.qrCode,
      recoveryCodes: result.recoveryCodes,
      // Em desenvolvimento, podemos retornar o segredo para facilitar os testes
      secret: config.app.env === 'development' ? result.secret : undefined
    });
  }

  /**
   * Desativa a autenticação de dois fatores
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async disable2FA(req, res) {
    const userId = req.user.id;
    const { token } = req.body;
    const ipAddress = req.ip;

    // Usar caso de uso para desativar 2FA
    const disable2FAUseCase = AuthUseCaseFactory.createDisable2FAUseCase();
    const result = await disable2FAUseCase.execute(userId, token, ipAddress);

    // Registrar evento de desativação 2FA
    await authService.logAuthEvent('2FA_DISABLED', 
      { id: userId, email: req.user.email }, 
      ipAddress
    );

    res.status(200).json({ 
      message: result.message || '2FA desativado com sucesso',
      success: result.success
    });
  }

  /**
   * Realiza logout invalidando tokens
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async logout(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    const refreshToken = req.cookies?.refreshToken;
    const ipAddress = req.ip;

    // Tratar token de acesso se fornecido
    if (token) {
      // Obter tempo restante para o token
      const remainingTime = tokenService.getRemainingTokenTime(token);
      
      // Adicionar à blacklist pelo tempo restante de validade ou por 1 hora mínimo
      await tokenService.blacklistToken(
        token,
        'access',
        remainingTime > 0 ? remainingTime : 3600 // Mínimo de 1 hora
      );
    }

    // Revogar refresh token se fornecido
    if (refreshToken) {
      await tokenService.revokeRefreshToken(refreshToken, ipAddress);
    }

    // Registrar evento de logout
    if (req.user) {
      await authService.logAuthEvent('LOGOUT', req.user, ipAddress);
    }

    // Limpar cookie
    this._clearRefreshTokenCookie(res);

    res.status(200).json({ 
      message: 'Logout realizado com sucesso'
    });
  }

  /**
   * Atualiza tokens usando refresh token
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async refreshToken(req, res) {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    const ipAddress = req.ip;

    if (!refreshToken) {
      throw new BadRequestError('Refresh token não fornecido');
    }

    // Usar o serviço centralizado para refresh de tokens
    const tokens = await tokenService.refreshTokens(refreshToken, ipAddress);

    // Atualizar cookie
    this._setRefreshTokenCookie(res, tokens.refreshToken);

    // Obter usuário do token para registro de auditoria
    const userInfo = tokenService.extractUserFromToken(tokens.accessToken);
    
    if (userInfo) {
      await authService.logAuthEvent('TOKEN_REFRESH', userInfo, ipAddress);
    }

    res.status(200).json({ accessToken: tokens.accessToken });
  }

  /**
   * Solicita redefinição de senha
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async requestPasswordReset(req, res) {
    const { email } = req.body;
    const ipAddress = req.ip;

    // Usar caso de uso para solicitar redefinição de senha
    const requestResetUseCase = AuthUseCaseFactory.createRequestPasswordResetUseCase();
    const result = await requestResetUseCase.execute(email, ipAddress);

    // Nota: o evento de auditoria é registrado dentro do caso de uso
    // apenas se o email for encontrado

    res.status(200).json({
      message: result.message || 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado'
    });
  }

  /**
   * Redefine a senha usando token
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async resetPassword(req, res) {
    const { token, newPassword } = req.body;
    const ipAddress = req.ip;

    if (!token || !newPassword) {
      throw new BadRequestError('Token e nova senha são obrigatórios');
    }

    // Usar caso de uso para redefinir senha
    const resetPasswordUseCase = AuthUseCaseFactory.createResetPasswordUseCase();
    const result = await resetPasswordUseCase.execute(token, newPassword, ipAddress);

    res.status(200).json({ 
      message: result.message || 'Senha redefinida com sucesso' 
    });
  }

  /**
   * Processa o callback da autenticação Google
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async googleCallback(req, res) {
    const ipAddress = req.ip;
    const user = req.user;

    if (!user) {
      throw new UnauthorizedError('Falha na autenticação com Google');
    }

    // Gerar tokens usando o serviço centralizado
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    this._setRefreshTokenCookie(res, refreshToken.token);

    // Registrar evento de login via Google
    await authService.logAuthEvent('LOGIN_GOOGLE', user, ipAddress);

    // Redirecionar para frontend com token
    const redirectUrl = `${config.oauth.google.redirectUrl}/login/oauth/success?token=${accessToken}`;
    res.redirect(redirectUrl);
  }

  /**
   * Valida o token atual (endpoint leve)
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async validateToken(req, res) {
    // O middleware de autenticação já verificou o token, 
    // então se chegamos aqui, o token é válido
    res.status(200).json({
      valid: true,
      userId: req.user.id,
      email: req.user.email,
      role: req.user.role
    });
  }

  /**
   * Busca informações resumidas do usuário atual
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async getCurrentUser(req, res) {
    // Buscar usuário usando o serviço centralizado
    const user = await authService.verifyUser(req.user.id, { 
      requireActive: true,
      requireVerified: false,
      checkLocked: false
    });
    
    res.status(200).json(user.toSafeObject());
  }

  /**
   * Define um cookie HTTP-only para o refresh token
   * @private
   * @param {Response} res Express Response
   * @param {string} token Refresh token
   */
  _setRefreshTokenCookie(res, token) {
    if (!token) return;
    
    res.cookie(
      'refreshToken', 
      token, 
      securityConfig.cookieOptions.refreshToken
    );
  }

  /**
   * Limpa o cookie de refresh token
   * @private
   * @param {Response} res Express Response
   */
  _clearRefreshTokenCookie(res) {
    const cookieOptions = { 
      ...securityConfig.cookieOptions.refreshToken, 
      maxAge: 0 
    };
    res.clearCookie('refreshToken', cookieOptions);
  }
}

// Exportar uma única instância do controlador
module.exports = new AuthController();