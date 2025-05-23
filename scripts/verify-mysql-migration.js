// scripts/verify-mysql-migration.js
const path = require('path');

// Script para verificar se todas as correções foram aplicadas
const verifyMigration = async () => {
  console.log('🔍 Verificando migração MySQL...\n');
  
  const checks = [
    {
      name: 'Imports de repositórios',
      files: [
        'src/domain/auth/factories/auth-use-case.factory.js',
        'src/infrastructure/security/auth.service.js',
        'src/infrastructure/security/token.service.js',
        'src/interfaces/api/controllers/auth.controller.js',
        'src/interfaces/api/controllers/rbac.controller.js',
        'src/interfaces/api/controllers/user.controller.js',
        'src/interfaces/api/validators/user.validator.js'
      ],
      check: (content) => {
        return !content.includes('mongodb/repositories') && 
               content.includes('mysql/repositories');
      }
    },
    {
      name: 'Validações UUID',
      files: [
        'src/interfaces/api/validators/rbac.validator.js',
        'src/interfaces/api/middlewares/validation.middleware.js'
      ],
      check: (content) => {
        return !content.includes('isMongoId()') && 
               content.includes('isUUID()');
      }
    },
    {
      name: 'Conexão MySQL no server.js',
      files: [
        'src/server.js',
        'src/infrastructure/utils/graceful-shutdown.js'
      ],
      check: (content) => {
        return !content.includes('mongodb/connection') && 
               content.includes('mysql/connection');
      }
    },
    {
      name: 'Modelos MySQL completos',
      files: [
        'src/infrastructure/database/mysql/models/index.js'
      ],
      check: (content) => {
        return content.includes('RefreshToken') && 
               content.includes('TokenBlacklist') &&
               content.includes('AuditLog') &&
               content.includes('LoginAttempt');
      }
    }
  ];
  
  let allPassed = true;
  
  for (const check of checks) {
    console.log(`📋 Verificando: ${check.name}`);
    
    for (const filePath of check.files) {
      try {
        const fs = require('fs');
        const fullPath = path.join(process.cwd(), filePath);
        
        if (!fs.existsSync(fullPath)) {
          console.log(`   ❌ Arquivo não encontrado: ${filePath}`);
          allPassed = false;
          continue;
        }
        
        const content = fs.readFileSync(fullPath, 'utf8');
        
        if (check.check(content)) {
          console.log(`   ✅ ${filePath}`);
        } else {
          console.log(`   ❌ ${filePath} - Correção necessária`);
          allPassed = false;
        }
      } catch (error) {
        console.log(`   ❌ Erro ao verificar ${filePath}: ${error.message}`);
        allPassed = false;
      }
    }
    console.log('');
  }
  
  if (allPassed) {
    console.log('🎉 Todas as verificações passaram! Migração MySQL completa.');
  } else {
    console.log('⚠️  Algumas verificações falharam. Revise as correções necessárias.');
  }
  
  return allPassed;
};

if (require.main === module) {
  verifyMigration()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Erro na verificação:', error);
      process.exit(1);
    });
}

module.exports = verifyMigration;