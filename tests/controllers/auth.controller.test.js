// tests/controllers/auth.controller.test.js
const mongoose = require('mongoose');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const app = require('../../app');
const User = require('../../models/user.model');
const tokenService = require('../../services/token.service');
const mailService = require('../../services/mail.service');

// Mock de serviços externos
jest.mock('../../services/mail.service', () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(true),
  sendResetPasswordEmail: jest.fn().mockResolvedValue(true),
  sendRecoveryCodes: jest.fn().mockResolvedValue(true)
}));

describe('Auth Controller', () => {
  describe('POST /auth/register', () => {
    it('deve registrar um novo usuário com sucesso', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'Test@123456',
        role: 'user'
      };

      const response = await request(app).post('/auth/register').send(userData);

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(userData.email);

      // Verificar se o usuário foi salvo no banco
      const user = await User.findOne({ email: userData.email });
      expect(user).toBeTruthy();
      expect(user.verified).toBe(false);
      expect(user.verifyToken).toBeTruthy();

      // Verificar se o e-mail foi enviado
      expect(mailService.sendVerificationEmail).toHaveBeenCalledWith(
        userData.email,
        expect.any(String)
      );
    });

    it('deve retornar erro ao tentar registrar com e-mail já existente', async () => {
      // Criar usuário de teste
      await User.create({
        email: 'exists@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user'
      });

      const userData = {
        email: 'exists@example.com',
        password: 'Test@123456'
      };

      const response = await request(app).post('/auth/register').send(userData);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('já está em uso');
    });

    it('deve retornar erro ao tentar registrar com dados inválidos', async () => {
      const userData = {
        email: 'invalid-email',
        password: '123' // senha muito curta
      };

      const response = await request(app).post('/auth/register').send(userData);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors.length).toBeGreaterThan(0);
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      // Criar usuário de teste verificado
      await User.create({
        email: 'user@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user',
        verified: true
      });

      // Criar usuário com 2FA ativado
      await User.create({
        email: '2fa@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user',
        verified: true,
        twoFactorEnabled: true,
        twoFactorSecret: 'JBSWY3DPEHPK3PXP' // Segredo de teste para TOTP
      });

      // Criar usuário não verificado
      await User.create({
        email: 'unverified@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user',
        verified: false
      });
    });

    it('deve autenticar um usuário com sucesso', async () => {
      const response = await request(app)
        .post('/auth/login')
        .set('x-app-key', process.env.APP_KEY) // Middleware AppKey
        .send({
          email: 'user@example.com',
          password: 'Test@123456'
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe('user@example.com');

      // Verificar cookie de refresh token
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'][0]).toContain('refreshToken');
    });

    it('deve requerer 2FA para um usuário com 2FA ativado', async () => {
      const response = await request(app)
        .post('/auth/login')
        .set('x-app-key', process.env.APP_KEY)
        .send({
          email: '2fa@example.com',
          password: 'Test@123456'
        });

      expect(response.status).toBe(206); // Partial Content
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('tempToken');
      expect(response.body.message).toContain('2FA necessário');
    });

    it('deve recusar login para usuário não verificado', async () => {
      const response = await request(app)
        .post('/auth/login')
        .set('x-app-key', process.env.APP_KEY)
        .send({
          email: 'unverified@example.com',
          password: 'Test@123456'
        });

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('não verificada');
    });

    it('deve recusar login com credenciais inválidas', async () => {
      const response = await request(app)
        .post('/auth/login')
        .set('x-app-key', process.env.APP_KEY)
        .send({
          email: 'user@example.com',
          password: 'WrongPassword'
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Credenciais inválidas');
    });
  });

  describe('POST /auth/logout', () => {
    let token;

    beforeEach(async () => {
      // Criar usuário e token para testes
      const user = await User.create({
        email: 'logout@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user',
        verified: true
      });

      token = tokenService.generateAccessToken({
        id: user._id,
        email: user.email,
        role: user.role
      });
    });

    it('deve fazer logout com sucesso', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Logout realizado com sucesso');

      // Verificar se o cookie foi limpo
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'][0]).toContain('refreshToken=;');
    });

    it('deve retornar erro para logout sem autenticação', async () => {
      const response = await request(app).post('/auth/logout');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Token não fornecido');
    });
  });

  describe('POST /auth/password-reset/request', () => {
    beforeEach(async () => {
      await User.create({
        email: 'reset@example.com',
        password: await bcrypt.hash('Test@123456', 10),
        role: 'user',
        verified: true
      });
    });

    it('deve solicitar redefinição de senha com sucesso', async () => {
      const response = await request(app).post('/auth/password-reset/request').send({
        email: 'reset@example.com'
      });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');

      // Verificar se o usuário foi atualizado com token de redefinição
      const user = await User.findOne({ email: 'reset@example.com' });
      expect(user.resetToken).toBeTruthy();
      expect(user.resetTokenExpires).toBeTruthy();

      // Verificar se o e-mail foi enviado
      expect(mailService.sendResetPasswordEmail).toHaveBeenCalledWith(
        'reset@example.com',
        expect.any(String)
      );
    });

    it('não deve revelar se o e-mail existe ou não', async () => {
      const response = await request(app).post('/auth/password-reset/request').send({
        email: 'nonexistent@example.com'
      });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');
      // A mensagem deve ser a mesma para não revelar se o e-mail existe
      expect(response.body.message).toContain('Instruções de redefinição enviadas');
    });
  });
});
