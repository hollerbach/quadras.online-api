// services/googleAuth.service.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('../models/user.model');
const config = require('../config/env.config');
const logger = require('./logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');
const tokenService = require('./token.service');
const userService = require('./user.service');
const auditService = require('./audit.service');

class GoogleAuthService {
  constructor() {
    this.initializeGoogleStrategy();
    this.initializeJwtStrategy();
  }

  /**
   * Inicializa estratégia de autenticação do Google
   */
  initializeGoogleStrategy() {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: `${config.app.baseUrl}/api/auth/google/callback`,
          scope: ['profile', 'email']
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            // Verificar se o usuário já existe com este googleId
            let user = await User.findOne({ 'oauth.google.id': profile.id });

            // Se não existir, verificar se o email já está registrado
            if (!user && profile.emails && profile.emails.length > 0) {
              const email = profile.emails[0].value;
              user = await User.findOne({ email });

              // Se o usuário existe mas não tem o Google ID, vincular
              if (user) {
                user.oauth = user.oauth || {};
                user.oauth.google = {
                  id: profile.id,
                  email: email,
                  name: profile.displayName,
                  picture: profile.photos?.[0]?.value
                };
                user.verified = true; // Emails do Google já são verificados
                await user.save();
                logger.info(`Usuário ${email} vinculou conta do Google`);
              }
            }

            // Se ainda não existe, criar um novo usuário
            if (!user) {
              const email = profile.emails?.[0]?.value;
              if (!email) {
                return done(new ApiError(400, 'Email não fornecido pelo Google'));
              }

              // Gerar senha aleatória segura (o usuário não a utilizará)
              const randomPassword = require('crypto').randomBytes(20).toString('hex');

              user = await userService.createUser({
                email,
                password: randomPassword,
                role: 'user',
                verified: true // Emails do Google já são verificados
              });

              user = await User.findOne({ email });
              user.oauth = {
                google: {
                  id: profile.id,
                  email: email,
                  name: profile.displayName,
                  picture: profile.photos?.[0]?.value
                }
              };

              await user.save();
              logger.info(`Novo usuário criado via Google: ${email}`);
            }

            return done(null, user);
          } catch (error) {
            logger.error(`Erro na autenticação Google: ${error.message}`);
            return done(error);
          }
        }
      )
    );

    // Serialização para sessão (se necessário)
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
   * Inicializa estratégia JWT para autenticação por token
   */
  initializeJwtStrategy() {
    const options = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.auth.jwt.secret
    };

    passport.use(
      new JwtStrategy(options, async (payload, done) => {
        try {
          // Verificar se o token está na blacklist
          const isBlacklisted = await tokenService.isTokenBlacklisted(
            ExtractJwt.fromAuthHeaderAsBearerToken()({}));
          
          if (isBlacklisted) {
            return done(null, false);
          }

          const user = await User.findById(payload.id);
          if (!user) {
            return done(null, false);
          }

          return done(null, user);
        } catch (error) {
          return done(error, false);
        }
      })
    );
  }

  /**
   * Gera tokens após autenticação OAuth bem-sucedida
   * @param {Object} user - Usuário autenticado
   * @param {string} ipAddress - Endereço IP da requisição
   * @returns {Promise<Object>} Tokens gerados
   */
  async generateAuthTokens(user, ipAddress) {
    // Atualizar último login
    user.lastLogin = Date.now();
    await user.save();

    // Gerar tokens
    const accessToken = tokenService.generateAccessToken({
      id: user._id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Registrar na auditoria
    await auditService.log({
      action: 'LOGIN_GOOGLE',
      userId: user._id,
      userEmail: user.email,
      ipAddress
    });

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        name: user.oauth?.google?.name || user.name
      }
    };
  }
}

module.exports = new GoogleAuthService();