// tests/setup.js
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

// Configurar variáveis de ambiente para testes
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.APP_KEY = 'test-app-key';

let mongoServer;

// Setup global para conectar ao MongoDB em memória
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();

  await mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
});

// Cleanup após todos os testes
afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Limpar coleções após cada teste
afterEach(async () => {
  const collections = mongoose.connection.collections;

  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany();
  }
});

// Silenciar console durante testes
global.console = {
  ...console,
  log: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
};
