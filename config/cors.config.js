const cors = require('cors');

// Lista de origens permitidas (coloque o domínio correto da produção)
const allowedOrigins = ['https://mercearia.digital'];

// Configuração customizada do CORS
const corsOptions = {
  origin: (origin, callback) => {
    // Permite requisições sem origem (ex: mobile apps ou curl) ou dentro da lista permitida
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    // Bloqueia outras origens
    return callback(new Error('CORS não permitido'));
  },
  credentials: true // Permite uso de cookies/autenticação
};

module.exports = cors(corsOptions);
