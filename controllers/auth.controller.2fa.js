const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/user.model');
const logger = require('../services/logger');

// Gera um segredo 2FA e um QR Code
exports.setup2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const secret = speakeasy.generateSecret({ name: `Mercearia (${user.email})` });

    user.twoFactorSecret = secret.base32;
    user.twoFactorEnabled = true;
    await user.save();

    const qrCode = await qrcode.toDataURL(secret.otpauth_url);
    logger.info(`2FA configurado para usuário ${user.email}`);
    res.status(200).json({ qrCode });
  } catch (err) {
    logger.error(`Erro ao configurar 2FA: ${err.message}`);
    res.status(500).json({ error: 'Erro ao configurar 2FA' });
  }
};

// Verifica o código TOTP do usuário
exports.verify2FA = async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id);

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      logger.warn(`Falha na verificação 2FA para ${user.email}`);
      return res.status(401).json({ message: 'Código 2FA inválido' });
    }

    logger.info(`2FA verificado com sucesso para ${user.email}`);
    res.status(200).json({ message: '2FA verificado com sucesso' });
  } catch (err) {
    logger.error(`Erro ao verificar 2FA: ${err.message}`);
    res.status(500).json({ error: 'Erro ao verificar 2FA' });
  }
};
