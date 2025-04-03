const User = require('../models/user.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mailService = require('./mail.service');

exports.register = async (req, res) => {
  const { email, password, role } = req.body;

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ message: 'Email já registrado' });

  const hashed = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const verifyTokenExpires = Date.now() + 1000 * 60 * 30;

  const user = await User.create({
    email,
    password: hashed,
    role,
    verified: false,
    verifyToken,
    verifyTokenExpires
  });

  await mailService.sendVerificationEmail(email, verifyToken);

  res.status(201).json({ message: 'Usuário criado. Verifique seu e-mail para ativar a conta.' });
};

exports.verifyEmail = async (req, res) => {
  const { token } = req.query;

  const user = await User.findOne({
    verifyToken: token,
    verifyTokenExpires: { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({ message: 'Token inválido ou expirado' });
  }

  user.verified = true;
  user.verifyToken = undefined;
  user.verifyTokenExpires = undefined;
  await user.save();

  res.json({ message: 'E-mail verificado com sucesso. Você já pode fazer login.' });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Credenciais inválidas' });

  if (!user.verified) {
    return res.status(403).json({ message: 'Conta não verificada. Verifique seu e-mail.' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: 'Credenciais inválidas' });

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  res.json({ token });
};

// logout, password reset... permanecem iguais
exports.logout = async (req, res) => {
  res.json({ message: 'Logout efetuado (cliente deve descartar token)' });
};

exports.requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Usuário não encontrado' });

  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpires = Date.now() + 15 * 60 * 1000;
  await user.save();

  await mailService.sendResetPasswordEmail(email, token);
  res.json({ message: 'Token enviado para o email' });
};

exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  const user = await User.findOne({
    resetToken: token,
    resetTokenExpires: { $gt: Date.now() }
  });

  if (!user) return res.status(400).json({ message: 'Token inválido ou expirado' });

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined;
  user.resetTokenExpires = undefined;
  await user.save();

  res.json({ message: 'Senha atualizada com sucesso' });
};
