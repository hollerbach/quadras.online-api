// controllers/auth.controller.js
const userService = require('../services/user.service');
const tokenService = require('../services/token.service');
const twoFactorService = require('../services/twoFactor.service');
const mailService = require('../services/mail.service');
const logger = require('../services/logger');
const { ApiError } = require('../middleware/errorHandler.middleware');
const config = require('../config/env.config');
const auditService = require('../services/audit.service'); // Novo serviço para logging de auditoria

class AuthController {
  /**
   * Registra um novo usuário
   */
  async register(req, res, next) {
    try {
      const { email, password, role, enable2FA } = req.body;
      
      // Criar o usuário usando o serviço
      const { user, verifyToken } = await userService.createUser({
        email, 
        password, 
        role, 
        enable2FA
      });
      
      // Enviar e-mail de verificação
      await mailService.sendVerificationEmail(email, verifyToken);

      // Registrar na auditoria
      await auditService.log({
        action: 'REGISTER',
        userEmail: email,
        ipAddress: req.ip,
        details: { role, enable2FA }
      });
      
      res.status(201).json({ 
        message: 'Usuário registrado com sucesso. Verifique seu e-mail para ativar a conta.',
        user
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verifica o e-mail do usuário
   */
  async verifyEmail(req, res, next) {
    try {
      const { token } = req.query;
      const result = await userService.verifyEmail(token);

      // Obter detalhes do usuário para auditoria
      const user = await User.findOne({ verifyToken: token });
      if (user) {
        await auditService.log({
          action: 'EMAIL_VERIFIED',
          userId: user._id,
          userEmail: user.email,
          ipAddress: req.ip
        });
      }

      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Autentica um usuário
   */
  async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip;
      
      // Validar credenciais
      const user = await userService.validateCredentials(email, password);
      
      // Resetar contagem de tentativas após login bem-sucedido
      await userService.resetLoginAttempts(user._id);
      
      // Verificar se 2FA está ativado
      if (user.twoFactorEnabled) {
        const tempToken = tokenService.generateTempToken({ id: user._id, email: user.email });
        logger.info(`Login inicial com 2FA pendente: ${email}`);

        // Registrar na auditoria
        await auditService.log({
          action: 'LOGIN_2FA_REQUIRED',
          userId: user._id,
          userEmail: email,
          ipAddress,
          details: { success: true }
        });

        return res.status(206).json({ 
          message: '2FA necessário', 
          tempToken 
        });
      }
      
      // Gerar tokens para usuário autenticado
      const accessToken = tokenService.generateAccessToken({ 
        id: user._id, 
        email: user.email,
        role: user.role 
      });
      
      const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);
      
      // Definir cookie HTTP-only para refresh token
      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        secure: config.app.env === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
      });
      
      // Registrar na auditoria
      await auditService.log({
        action: 'LOGIN',
        userId: user._id,
        userEmail: user.email,
        ipAddress,
        details: { user2FA: user.twoFactorEnabled }
      });

      logger.info(`Login bem-sucedido: ${email}`);
      res.status(200).json({ 
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          role: user.role
        }
      });
    } catch (error) {
      // Se for erro de credenciais, incrementar contador de tentativas de login
      if (error.statusCode === 401 && req.body.email) {
        const lockInfo = await userService.incrementLoginAttempts(req.body.email);
        
        // Se temos informações de bloqueio, registrar na auditoria
        if (lockInfo) {
          await auditService.log({
            action: 'LOGIN_FAILED',
            userEmail: req.body.email,
            ipAddress: req.ip,
            details: { 
              attemptsRemaining: lockInfo.attemptsRemaining,
              isLocked: lockInfo.isLocked
            }
          });
          
          // Se a conta foi bloqueada, modificar a mensagem de erro
          if (lockInfo.isLocked) {
            error = new ApiError(429, 'Conta temporariamente bloqueada por excesso de tentativas. Tente novamente mais tarde.');
          }
        }
      }
      
      next(error);
    }
  }

  /**
   * Verifica o token 2FA e completa o login
   */
  async verify2FA(req, res, next) {
    try {
      const { token, tempToken } = req.body;
      const ipAddress = req.ip;
      
      // Verificar e decodificar o token temporário
      const decoded = tokenService.verifyAccessToken(tempToken);
      
      if (!decoded || !decoded.is2FA) {
        throw new ApiError(400, 'Token temporário inválido');
      }
      
      const user = await userService.findById(decoded.id);
      
      if (!user || !user.twoFactorEnabled) {
        throw new ApiError(400, '2FA não está habilitado para este usuário');
      }
      
      // Verificar o token TOTP
      const verified = twoFactorService.verifyToken(user.twoFactorSecret, token);
      
      if (!verified) {
        logger.warn(`Código 2FA inválido: ${user.email}`);
        
        // Registrar tentativa falha na auditoria
        await auditService.log({
          action: 'LOGIN_2FA_FAILED',
          userId: user._id,
          userEmail: user.email,
          ipAddress
        });
        
        throw new ApiError(401, 'Código 2FA inválido');
      }
      
      // Gerar tokens para usuário autenticado com 2FA
      const accessToken = tokenService.generateAccessToken({ 
        id: user._id, 
        email: user.email,
        role: user.role 
      });
      
      const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);
      
      // Definir cookie HTTP-only para refresh token
      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        secure: config.app.env === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
      });
      
      // Registrar na auditoria
      await auditService.log({
        action: 'LOGIN_2FA_SUCCESS',
        userId: user._id,
        userEmail: user.email,
        ipAddress
      });
      
      logger.info(`2FA verificado com sucesso: ${user.email}`);
      res.status(200).json({ 
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          role: user.role
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Autentica com código de recuperação 2FA
   * Novo método para usar códigos de recuperação
   */
  async verify2FARecovery(req, res, next) {
    try {
      const { code, tempToken } = req.body;
      const ipAddress = req.ip;
      
      // Verificar e decodificar o token temporário
      const decoded = tokenService.verifyAccessToken(tempToken);
      
      if (!decoded || !decoded.is2FA) {
        throw new ApiError(400, 'Token temporário inválido');
      }
      
      const user = await userService.findById(decoded.id);
      
      if (!user || !user.twoFactorEnabled) {
        throw new ApiError(400, '2FA não está habilitado para este usuário');
      }
      
      // Verificar o código de recuperação
      const recoveryCodeResult = await user.validateRecoveryCode(code);
      
      if (!recoveryCodeResult) {
        logger.warn(`Código de recuperação 2FA inválido: ${user.email}`);
        
        // Registrar tentativa falha na auditoria
        await auditService.log({
          action: 'LOGIN_2FA_RECOVERY_FAILED',
          userId: user._id,
          userEmail: user.email,
          ipAddress
        });
        
        throw new ApiError(401, 'Código de recuperação inválido');
      }
      
      // Código válido, gerar novos tokens
      const accessToken = tokenService.generateAccessToken({ 
        id: user._id, 
        email: user.email,
        role: user.role 
      });
      
      const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);
      
      // Definir cookie HTTP-only para refresh token
      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        secure: config.app.env === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
      });
      
      // Registrar na auditoria
      await auditService.log({
        action: 'LOGIN_2FA_RECOVERY_SUCCESS',
        userId: user._id,
        userEmail: user.email,
        ipAddress
      });
      
      logger.info(`Login via código de recuperação 2FA: ${user.email}`);
      res.status(200).json({ 
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          role: user.role
        },
        recoveryCodesRemaining: user.recoveryCodes.filter(c => !c.used).length
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Configura a autenticação de dois fatores para um usuário
   */
  async setup2FA(req, res, next) {
    try {
      const userId = req.user.id;
      
      // Buscar usuário
      const user = await userService.findById(userId);
      
      // Gerar segredo para 2FA
      const secret = twoFactorService.generateSecret(user.email);
      
      // Salvar segredo no banco de dados
      await userService.enable2FA(userId, secret.base32);
      
      // Gerar QR Code para configuração
      const qrCode = await twoFactorService.generateQRCode(secret.otpauth_url);
      
      // Gerar códigos de recuperação
      const recoveryCodes = twoFactorService.generateRecoveryCodes();
      
      // Salvar códigos de recuperação
      await user.setRecoveryCodes(recoveryCodes);
      
      // Enviar códigos por email como backup
      await mailService.sendRecoveryCodes(user.email, recoveryCodes);
      
      // Registrar na auditoria
      await auditService.log({
        action: '2FA_SETUP',
        userId: user._id,
        userEmail: user.email,
        ipAddress: req.ip
      });
      
      logger.info(`2FA configurado para usuário ${user.email}`);
      res.status(200).json({ 
        qrCode,
        recoveryCodes,
        secret: config.app.env === 'development' ? secret.base32 : undefined // Enviar apenas em ambiente de desenvolvimento
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Desativa a autenticação de dois fatores
   */
  async disable2FA(req, res, next) {
    try {
      const userId = req.user.id;
      const { token } = req.body;
      
      // Buscar usuário
      const user = await userService.findById(userId);
      
      // Verificar token antes de desativar
      const verified = twoFactorService.verifyToken(user.twoFactorSecret, token);
      
      if (!verified) {
        throw new ApiError(401, 'Código 2FA inválido');
      }
      
      // Desativar 2FA
      await userService.disable2FA(userId);
      
      // Registrar na auditoria
      await auditService.log({
        action: '2FA_DISABLED',
        userId: user._id,
        userEmail: user.email,
        ipAddress: req.ip
      });
      
      logger.info(`2FA desativado para usuário ${user.email}`);
      res.status(200).json({ message: '2FA desativado com sucesso' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Realiza logout invalidando tokens
   */
  async logout(req, res, next) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      const refreshToken = req.cookies.refreshToken;
      const ipAddress = req.ip;
      
      if (token) {
        // Obter payload do token sem verificar assinatura
        const decoded = tokenService.decodeToken(token);
        
        // Adicionar à blacklist pelo tempo restante de validade
        if (decoded.exp) {
          const timeToExpire = decoded.exp - Math.floor(Date.now() / 1000);
          await tokenService.blacklistToken(token, 'access', timeToExpire > 0 ? timeToExpire : 3600);
        }
      }
      
      if (refreshToken) {
        // Revogar refresh token
        await tokenService.revokeRefreshToken(refreshToken, ipAddress);
        
        // Limpar cookie
        res.clearCookie('refreshToken');
      }
      
      // Registrar na auditoria
      await auditService.log({
        action: 'LOGOUT',
        userId: req.user?.id,
        userEmail: req.user?.email,
        ipAddress
      });
      
      logger.info(`Logout efetuado: ${req.user?.email || 'Usuário anônimo'}`);
      res.status(200).json({ message: 'Logout realizado com sucesso' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Atualiza tokens usando refresh token
   */
  async refreshToken(req, res, next) {
    try {
      const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
      const ipAddress = req.ip;
      
      if (!refreshToken) {
        throw new ApiError(400, 'Refresh token é obrigatório');
      }
      
      // Gerar novos tokens
      const { accessToken, refreshToken: newRefreshToken } = await tokenService.refreshTokens(
        refreshToken,
        ipAddress
      );
      
      // Atualizar cookie
      res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: config.app.env === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
      });
      
      // Registrar na auditoria 
      // Obter payload do token para registrar usuário
      const decoded = tokenService.decodeToken(accessToken);
      if (decoded && decoded.id) {
        await auditService.log({
          action: 'TOKEN_REFRESH',
          userId: decoded.id,
          userEmail: decoded.email,
          ipAddress
        });
      }
      
      res.status(200).json({ accessToken });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Solicita redefinição de senha
   */
  async requestPasswordReset(req, res, next) {
    try {
      const { email } = req.body;
      
      // Gerar token de redefinição
      const { resetToken } = await userService.createPasswordResetToken(email);
      
      // Enviar e-mail com token
      await mailService.sendResetPasswordEmail(email, resetToken);

      // Registrar na auditoria
      // Buscar usuário para obter o ID (se existir)
      const user = await User.findOne({ email });
      if (user) {
        await auditService.log({
          action: 'PASSWORD_RESET_REQUEST',
          userId: user._id,
          userEmail: email,
          ipAddress: req.ip
        });
      }
      
      res.status(200).json({ message: 'Instruções de redefinição enviadas para o e-mail' });
    } catch (error) {
      // Não revelar se e-mail existe
      if (error.statusCode === 404) {
        res.status(200).json({ message: 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado' });
      } else {
        next(error);
      }
    }
  }

  /**
   * Redefine a senha usando token
   */
  async resetPassword(req, res, next) {
    try {
      const { token, newPassword } = req.body;
      
      // Redefinir senha
      const result = await userService.resetPassword(token, newPassword);
      
      // Registrar na auditoria
      // Buscar usuário pelo token para obter ID
      const user = await User.findOne({ 
        resetToken: token,
        resetTokenExpires: { $gt: Date.now() } 
      });
      
      if (user) {
        await auditService.log({
          action: 'PASSWORD_RESET_COMPLETE',
          userId: user._id,
          userEmail: user.email,
          ipAddress: req.ip
        });
      }
      
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }
}

// Exportar singleton
module.exports = new AuthController();