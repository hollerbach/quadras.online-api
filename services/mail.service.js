const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT, 10),
  secure: process.env.EMAIL_PORT == 465, // true para SSL (465), false para TLS (587)
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


exports.sendResetPasswordEmail = async (to, token) => {
  const link = `http://localhost:3000/reset-password?token=${token}`;
  await transporter.sendMail({
    from: `"Auth API" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Redefinição de senha',
    html: `<p>Você solicitou redefinir sua senha.</p><p>Clique <a href="${link}">aqui</a> para redefinir. O link expira em 15 minutos.</p>`
  });
};

exports.sendVerificationEmail = async (to, token) => {
  const link = `http://localhost:3000/api/auth/verify-email?token=${token}`;
  await transporter.sendMail({
    from: `"Auth API" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Confirmação de Registro',
    html: `<p>Obrigado por se registrar.</p><p>Clique <a href="${link}">aqui para confirmar seu e-mail</a>.</p><p>Este link expira em 30 minutos.</p>`
  });
};
