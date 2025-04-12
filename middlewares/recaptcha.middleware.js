const axios = require('axios');

module.exports = async (req, res, next) => {
  const token = req.body.recaptchaToken;
  if (!token) return res.status(400).json({ message: 'reCAPTCHA ausente' });

  try {
    const response = await axios.post(`https://www.google.com/recaptcha/siteverify`, null, {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    });

    const { success, score } = response.data;

    if (!success || score < 0.5) {
      return res.status(403).json({ message: 'reCAPTCHA inválido ou suspeito' });
    }

    next();
  } catch (err) {
    return res.status(500).json({ message: 'Erro na verificação do reCAPTCHA' });
  }
};
