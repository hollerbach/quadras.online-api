// src/interfaces/api/controllers/auth.controller.js
const AuthUseCaseFactory = require('../../../domain/auth/factories/auth-use-case.factory');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const authService = require('../../../infrastructure/security/auth.service');
const tokenService = require('../../../infrastructure/security/token.service');
const twoFactorService = require('../../../infrastructure/security/two-factor.service');
const config = require('../../../infrastructure/config');
const securityConfig = require('../../../infrastructure/security/security.config');
const logger = require('../../../infrastructure/logging/logger');
const { BadRequestError, UnauthorizedError } = require('../../../shared/errors/api-error');

// Auditoria (opcional)
let auditService;
try {
  auditService = require('../../../infrastructure/logging/audit.service');
} catch (error) {
  console.warn('Serviço de auditoria não disponível');
}

/**
 * Controlador para rotas de autenticação
 * Responsável por orquestrar os casos de uso e transformar seus resultados em respostas HTTP
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

    // Usar o serviço de autenticação para verificar credenciais
    // Isso centraliza a lógica de autenticação e evita duplicação
    const user = await authService.verifyCredentials(email, password, ipAddress);

    // Verificar se 2FA está ativado
    if (user.twoFactorEnabled) {
      const tempToken = tokenService.generateTempToken({ 
        id: user.id, 
        email: user.email,
        is2FA: true
      });

      this._logAuditEvent('LOGIN_2FA_REQUIRED', user, ipAddress);

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
    this._logAuditEvent('LOGIN', user, ipAddress, { 
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

    // Usar caso de uso para verificação 2FA
    const verify2FAUseCase = AuthUseCaseFactory.createVerify2FAUseCase();
    const result = await verify2FAUseCase.execute(token, tempToken, ipAddress);

    // Definir cookie HTTP-only para refresh token
    this._setRefreshTokenCookie(res, result.refreshToken);

    // Retornar apenas o token de acesso e usuário (não o refresh token)
    res.status(200).json({
      accessToken: result.accessToken,
      user: result.user
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

    // Verificar e decodificar o token temporário
    const decoded = tokenService.verifyAccessToken(tempToken);

    if (!decoded || !decoded.is2FA) {
      throw new BadRequestError('Token temporário inválido para fluxo 2FA');
    }

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
      this._logAuditEvent('LOGIN_2FA_RECOVERY_FAILED', user, ipAddress);
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

    // Registrar na auditoria
    this._logAuditEvent('LOGIN_2FA_RECOVERY_SUCCESS', user, ipAddress);

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
    const refreshToken = req.cookies.refreshToken;
    const ipAddress = req.ip;

    // Usar caso de uso para logout
    const logoutUseCase = AuthUseCaseFactory.createLogoutUseCase();
    const result = await logoutUseCase.execute(token, refreshToken, req.user, ipAddress);

    // Limpar cookie
    this._clearRefreshTokenCookie(res);

    res.status(200).json({ 
      message: result.message || 'Logout realizado com sucesso'
    });
  }

  /**
   * Atualiza tokens usando refresh token
   * @param {Request} req Express Request
   * @param {Response} res Express Response
   */
  async refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    const ipAddress = req.ip;

    if (!refreshToken) {
      throw new BadRequestError('Refresh token não fornecido');
    }

    // Usar caso de uso para refresh de tokens
    const refreshTokensUseCase = AuthUseCaseFactory.createRefreshTokensUseCase();
    const result = await refreshTokensUseCase.execute(refreshToken, ipAddress);

    // Atualizar cookie
    this._setRefreshTokenCookie(res, result.refreshToken);

    res.status(200).json({ accessToken: result.accessToken });
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

    // Gerar tokens
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token (será enviado nas próximas requisições)
    this._setRefreshTokenCookie(res, refreshToken.token);

    // Registrar na auditoria
    this._logAuditEvent('LOGIN_GOOGLE', user, ipAddress);

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
    // req.user já contém informações básicas, mas vamos buscar dados completos
    const user = await userRepository.findById(req.user.id);
    
    if (!user) {
      throw new BadRequestError('Usuário não encontrado');
    }
    
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

  /**
   * Registra um evento de auditoria
   * @private
   * @param {string} action Ação a ser registrada
   * @param {Object} user Usuário relacionado
   * @param {string} ipAddress Endereço IP
   * @param {Object} details Detalhes adicionais
   */
  async _logAuditEvent(action, user, ipAddress, details = {}) {
    if (auditService) {
      await auditService.log({
        action,
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details
      });
    }
    
    logger.info(`Auth: ${action} - ${user.email} (${ipAddress})`);
  }
}

// Exportar uma única instância do controlador
module.exports = new AuthController();