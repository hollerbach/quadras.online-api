require('dotenv').config();
const app = require('./app');
const mongoose = require('mongoose');

const {
  DB_USER,
  DB_PASS,
  DB_NAME,
  MONGODB_CLUSTER,
  MONGODB_APP,
  PORT
} = process.env;

// Monta a URI com segurança
const uri = `mongodb+srv://${encodeURIComponent(DB_USER)}:${encodeURIComponent(DB_PASS)}@${MONGODB_CLUSTER}/${DB_NAME}?retryWrites=true&w=majority&appName=${MONGODB_APP}`;

mongoose.connect(uri)
  .then(() => {
    console.log('✅ Conectado ao MongoDB Atlas');
    app.listen(PORT, () => {
      console.log(`🚀 Server rodando na porta ${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ Erro ao conectar ao MongoDB Atlas:', err.message);
  });
