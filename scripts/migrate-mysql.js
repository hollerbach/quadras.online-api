// scripts/migrate-mysql.js
require('dotenv').config();
const { Sequelize } = require('sequelize');
const config = require('../infrastructure/config');
const defineModels = require('../infrastructure/database/mysql/models');
const fs = require('fs');
const path = require('path');

const migrateTables = async () => {
  let sequelize;
  
  try {
    // Conectar ao MySQL
    sequelize = new Sequelize(
      config.db.mysql.database,
      config.db.mysql.username,
      config.db.mysql.password,
      {
        host: config.db.mysql.host,
        port: config.db.mysql.port,
        dialect: 'mysql',
        logging: console.log
      }
    );

    await sequelize.authenticate();
    console.log('✅ Conectado ao MySQL');

    // Obter modelos
    const models = defineModels();

    // Definir a ordem correta para criação das tabelas
    const tablesOrder = [
      'users',
      'user_recovery_codes',
      'user_oauth',
      'permissions',
      'resources',
      'roles',
      'role_permissions',
      'role_permission_resources',
      'user_roles',
      'refresh_tokens',
      'token_blacklist',
      'audit_logs'
    ];

    console.log('🔄 Criando/atualizando estrutura das tabelas...');

    // Executar o script SQL diretamente
    const sqlScript = fs.readFileSync(
      path.join(__dirname, '../infrastructure/database/mysql/migrations/01_initial_schema.sql'),
      'utf8'
    );

    // Dividir o script em comandos individuais
    const commands = sqlScript
      .split(';')
      .map(cmd => cmd.trim())
      .filter(cmd => cmd.length > 0 && !cmd.startsWith('--'));

    for (const command of commands) {
      if (command.trim()) {
        try {
          await sequelize.query(command);
        } catch (error) {
          // Ignorar erros de tabela já existente
          if (!error.message.includes('already exists')) {
            console.warn(`⚠️  Aviso ao executar comando: ${error.message}`);
          }
        }
      }
    }

    console.log('✅ Estrutura das tabelas criada/atualizada com sucesso');

    // Sincronizar modelos com o banco (alter: true para ajustar diferenças)
    await sequelize.sync({ alter: true });
    console.log('✅ Modelos sincronizados com o banco de dados');

    // Verificar se as tabelas foram criadas
    const tables = await sequelize.getQueryInterface().showAllTables();
    console.log('📋 Tabelas no banco:', tables);

    console.log('🎉 Migração concluída com sucesso!');

  } catch (error) {
    console.error('❌ Erro durante a migração:', error);
    process.exit(1);
  } finally {
    if (sequelize) {
      await sequelize.close();
      console.log('🔌 Conexão fechada');
    }
  }
};

// Executar migração
migrateTables();