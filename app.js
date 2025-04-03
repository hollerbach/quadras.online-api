const express = require('express');
const app = express();
const cors = require('./config/cors.config');
const authRoutes = require('./routes/auth.routes');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');

const swaggerDocument = YAML.load('./docs/swagger.yaml');

// Middlewares globais
app.use(cors); // ✅ Aplicando CORS corretamente
app.use(express.json());

// Rotas
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use('/api/auth', authRoutes);

module.exports = app;
