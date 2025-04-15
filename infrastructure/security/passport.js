// src/infrastructure/security/passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const userRepository = require('../database/mongodb/repositories/user.repository');
const config = require('../config');
const logger = require('../logging/logger');
const { NotFoundError } = require('../../shared/errors/api-error');

/**
 * Configuração e inicialização das estratégias de autenticação
 */
const initializePassport = () => {
  // Estratégia JWT
  const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: config.auth.jwt.secret
  };

  passport.use(
    new JwtStrategy(jwtOptions, async (payload, done) => {
      try {
        const user = await userRepository.findById(payload.id);
        
        if (!user) {
          return done(null, false);
        }

        return done(null, user);
      } catch (error) {
        return done(error, false);
      }
    })
  );

  // Estratégia Google OAuth2
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.oauth.google.clientId,
        clientSecret: config.oauth.google.clientSecret,
        callbackURL: config.oauth.google.callbackUrl,
        scope: ['profile', 'email']
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // Verificar se o usuário já existe com este googleId
          let user = await userRepository.findByOAuthId('google', profile.id);

          // Se não existir, verificar se o email já está registrado
          if (!user && profile.emails && profile.emails.length > 0) {
            const email = profile.emails[0].value;
            user = await userRepository.findByEmail(email);

            // Se o usuário existe mas não tem o Google ID, vincular
            if (user) {
              user.linkOAuthAccount('google', {
                id: profile.id,
                email: email,
                name: profile.displayName,
                picture: profile.photos?.[0]?.value
              });
              
              // Usuários do Google são considerados verificados
              if (!user.verified) {
                user.verifyEmail();
              }
              
              await userRepository.save(user);
              logger.info(`Usuário ${email} vinculou conta do Google`);
            }
          }

          // Se ainda não existe, criar um novo usuário
          if (!user) {
            const email = profile.emails?.[0]?.value;
            if (!email) {
              return done(new NotFoundError('Email não fornecido pelo Google'));
            }

            // Gerar senha aleatória segura (o usuário não a utilizará)
            const crypto = require('crypto');
            const randomPassword = crypto.randomBytes(20).toString('hex');

            // Criar novo usuário
            user = await userRepository.create({
              email,
              password: randomPassword,
              role: 'user',
              verified: true, // Contas OAuth são verificadas por padrão
              oauth: {
                google: {
                  id: profile.id,
                  email: email,
                  name: profile.displayName,
                  picture: profile.photos?.[0]?.value
                }
              },
              name: profile.displayName || profile.name?.givenName,
              surname: profile.name?.familyName
            });

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

  // Serialização (necessária mesmo sem sessões para alguns casos)
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await userRepository.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  logger.info('Passport configurado com sucesso');
};

// Inicializar Passport
initializePassport();

module.exports = passport;