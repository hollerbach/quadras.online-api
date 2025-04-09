// 1. Create a new service file for OAuth: services/oauth.service.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/user.model');
const logger = require('./logger');
const config = require('../config/env.config');
const userService = require('./user.service');
const auditService = require('./audit.service');

class OAuthService {
  constructor() {
    this.setupGoogleStrategy();
  }

  /**
   * Configura a estratégia de autenticação Google OAuth 2.0
   */
  setupGoogleStrategy() {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientID,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: `${config.app.baseUrl}/api/auth/google/callback`,
          passReqToCallback: true
        },
        async (req, accessToken, refreshToken, profile, done) => {
          try {
            // Verificar se já existe usuário com este ID Google
            let user = await User.findOne({ 'oauth.google.id': profile.id });
            const ipAddress = req.ip || 'unknown';

            if (user) {
              // Usuário existe, atualizar informações se necessário
              user.oauth.google.lastLogin = new Date();
              user.oauth.google.email = profile.emails[0].value;
              user.oauth.google.name = profile.displayName;
              user.oauth.google.picture = profile.photos[0]?.value;
              await user.save();

              // Registrar na auditoria
              await auditService.log({
                action: 'GOOGLE_LOGIN',
                userId: user._id,
                userEmail: user.email,
                ipAddress,
                details: { provider: 'google' }
              });

              return done(null, user);
            } else {
              // Verificar se existe usuário com o mesmo email
              user = await User.findOne({ email: profile.emails[0].value });

              if (user) {
                // Vincular conta Google ao usuário existente
                user.oauth = user.oauth || {};
                user.oauth.google = {
                  id: profile.id,
                  email: profile.emails[0].value,
                  name: profile.displayName,
                  picture: profile.photos[0]?.value,
                  lastLogin: new Date()
                };
                await user.save();

                // Registrar na auditoria
                await auditService.log({
                  action: 'GOOGLE_ACCOUNT_LINKED',
                  userId: user._id,
                  userEmail: user.email,
                  ipAddress,
                  details: { provider: 'google' }
                });

                return done(null, user);
              } else {
                // Criar novo usuário com Google OAuth
                const newUser = new User({
                  email: profile.emails[0].value,
                  // Senha aleatória para usuários OAuth (não utilizada)
                  password: Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2),
                  verified: true, // Emails do Google já são verificados
                  role: 'user',
                  oauth: {
                    google: {
                      id: profile.id,
                      email: profile.emails[0].value,
                      name: profile.displayName,
                      picture: profile.photos[0]?.value,
                      lastLogin: new Date()
                    }
                  }
                });

                await newUser.save();

                // Registrar na auditoria
                await auditService.log({
                  action: 'GOOGLE_REGISTER',
                  userId: newUser._id,
                  userEmail: newUser.email,
                  ipAddress,
                  details: { provider: 'google' }
                });

                return done(null, newUser);
              }
            }
          } catch (error) {
            logger.error(`Erro na autenticação Google: ${error.message}`);
            return done(error);
          }
        }
      )
    );

    // Serialização e deserialização de usuários para sessão (se necessário)
    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
      try {
        const user = await User.findById(id);
        done(null, user);
      } catch (error) {
        done(error);
      }
    });
  }

  /**
   * Processa resultado da autenticação Google
   * @param {Object} user - Usuário autenticado
   * @param {string} ipAddress - Endereço IP do usuário
   * @returns {Promise<Object>} Tokens de acesso
   */
  async processGoogleLogin(user, ipAddress) {
    try {
      const tokenService = require('./token.service');
      
      // Gerar tokens para usuário autenticado
      const accessToken = tokenService.generateAccessToken({
        id: user._id,
        email: user.email,
        role: user.role
      });

      const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

      // Atualizar último login
      await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

      return {
        accessToken,
        refreshToken: refreshToken.token,
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
          oauth: user.oauth?.google ? {
            name: user.oauth.google.name,
            picture: user.oauth.google.picture
          } : null
        }
      };
    } catch (error) {
      logger.error(`Erro ao processar login Google: ${error.message}`);
      throw error;
    }
  }

  /**
   * Desvincula conta Google de um usuário
   * @param {string} userId - ID do usuário
   * @returns {Promise<Object>} Resultado da operação
   */
  async unlinkGoogleAccount(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('Usuário não encontrado');
      }

      // Verificar se usuário tem senha definida antes de desvincular
      if (!user.password || user.password.length < 30) {
        throw new Error('Você precisa definir uma senha antes de desvincular sua conta Google');
      }

      // Remover vinculação Google
      if (user.oauth && user.oauth.google) {
        user.oauth.google = undefined;
        await user.save();
      }

      return { message: 'Conta Google desvinculada com sucesso' };
    } catch (error) {
      logger.error(`Erro ao desvincular conta Google: ${error.message}`);
      throw error;
    }
  }
}

module.exports = new OAuthService();
