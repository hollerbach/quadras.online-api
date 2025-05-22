// tests/setup.js
const { Sequelize } = require('sequelize');
const config = require('../src/infrastructure/config');
const defineModels = require('../src/infrastructure/database/mysql/models');

// Configuração para banco de testes em memória
const testConfig = {
  dialect: 'sqlite',
  storage: ':memory:',
  logging: false,
  define: {
    timestamps: true,
    underscored: true,
    paranoid: false
  }
};

let sequelize;
let models;

// Setup global antes de todos os testes
beforeAll(async () => {
  // Criar instância do Sequelize para testes
  sequelize = new Sequelize(testConfig);
  
  // Definir modelos no contexto de teste
  models = defineModels(sequelize);
  
  // Sincronizar todas as tabelas
  await sequelize.sync({ force: true });
  
  // Disponibilizar globalmente
  global.sequelize = sequelize;
  global.models = models;
});

// Cleanup após todos os testes
afterAll(async () => {
  if (sequelize) {
    await sequelize.close();
  }
});

// Limpar dados entre testes
beforeEach(async () => {
  if (models) {
    // Limpar todas as tabelas em ordem reversa para evitar problemas de FK
    const tableNames = [
      'AuditLog',
      'TokenBlacklist', 
      'RefreshToken',
      'UserRole',
      'RolePermissionResource',
      'RolePermission',
      'Role',
      'Resource',
      'Permission',
      'UserOAuth',
      'UserRecoveryCode',
      'User'
    ];
    
    for (const tableName of tableNames) {
      if (models[tableName]) {
        await models[tableName].destroy({ where: {}, force: true });
      }
    }
  }
});

module.exports = {
  sequelize,
  models
};