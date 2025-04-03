const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const logger = require('../services/logger');
const speakeasy = require('speakeasy');

// Gerar JWT completo (após login ou 2FA)
const generateToken = (user) => {
  return jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Gerar token temporário para quem usa 2FA
const generateTempToken = (user) => {
  return jwt.sign({ id: user._id, is2FA: true }, process.env.JWT_SECRET, { expiresIn: '5m' });
};

// Registro de novo usuário, com ou sem 2FA
exports.register = async (req, res) => {
  try {
    const { email, password, enable2FA } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Usuário já existe' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
      twoFactorEnabled: enable2FA || false
    });

    if (enable2FA) {
      const secret = speakeasy.generateSecret({ name: `Mercearia (${email})` });
      user.twoFactorSecret = secret.base32;
    }

    await user.save();
    logger.info(`Novo registro: ${email} (2FA: ${enable2FA ? 'ativado' : 'desativado'})`);

    res.status(201).json({ message: 'Usuário registrado com sucesso', twoFactorEnabled: enable2FA });
  } catch (err) {
    logger.error(`Erro no registro: ${err.message}`);
    res.status(500).json({ message: 'Erro ao registrar usuário' });
  }
};

// Login com verificação condicional de 2FA
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Credenciais inválidas' });

    if (user.twoFactorEnabled) {
      const tempToken = generateTempToken(user);
      logger.info(`Login inicial com 2FA pendente: ${email}`);
      return res.status(206).json({ message: '2FA necessário', tempToken });
    }

    const token = generateToken(user);
    logger.info(`Login sem 2FA: ${email}`);
    res.status(200).json({ token });
  } catch (err) {
    logger.error(`Erro no login: ${err.message}`);
    res.status(500).json({ message: 'Erro ao autenticar' });
  }
};

// Verificação do token TOTP
exports.verify2FA = async (req, res) => {
  try {
    const { token, tempToken } = req.body;
    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({ message: '2FA não está habilitado para este usuário' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      logger.warn(`Código 2FA inválido: ${user.email}`);
      return res.status(401).json({ message: 'Código 2FA inválido' });
    }

    const fullToken = generateToken(user);
    logger.info(`2FA verificado com sucesso: ${user.email}`);
    res.status(200).json({ token: fullToken });
  } catch (err) {
    logger.error(`Erro ao verificar 2FA: ${err.message}`);
    res.status(500).json({ message: 'Erro ao verificar 2FA' });
  }
};
