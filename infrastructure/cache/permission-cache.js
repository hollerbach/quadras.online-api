// src/infrastructure/cache/permission-cache.js
const NodeCache = require('node-cache');

// Cache com TTL de 5 minutos e limpeza automática a cada 10 minutos
const cache = new NodeCache({ stdTTL: 300, checkperiod: 600 });

/**
 * Serviço de cache para permissões
 */
class PermissionCache {
  /**
   * Gera uma chave de cache para verificação de permissão
   * @param {string} userId ID do usuário
   * @param {string} permissionCode Código da permissão
   * @param {string|null} resourcePath Caminho do recurso opcional
   * @returns {string} Chave de cache
   */
  generateKey(userId, permissionCode, resourcePath = null) {
    return `perm:${userId}:${permissionCode}:${resourcePath || 'global'}`;
  }

  /**
   * Obtém um resultado de verificação de permissão do cache
   * @param {string} userId ID do usuário
   * @param {string} permissionCode Código da permissão
   * @param {string|null} resourcePath Caminho do recurso opcional
   * @returns {boolean|undefined} Resultado ou undefined se não estiver em cache
   */
  get(userId, permissionCode, resourcePath = null) {
    const key = this.generateKey(userId, permissionCode, resourcePath);
    return cache.get(key);
  }

  /**
   * Armazena um resultado de verificação de permissão no cache
   * @param {string} userId ID do usuário
   * @param {string} permissionCode Código da permissão
   * @param {string|null} resourcePath Caminho do recurso opcional
   * @param {boolean} result Resultado da verificação
   * @param {number} ttl Tempo de vida em segundos (opcional)
   */
  set(userId, permissionCode, resourcePath = null, result, ttl = 300) {
    const key = this.generateKey(userId, permissionCode, resourcePath);
    cache.set(key, result, ttl);
  }

  /**
   * Limpa o cache para um usuário específico
   * @param {string} userId ID do usuário
   */
  invalidateUser(userId) {
    const keys = cache.keys();
    const userKeys = keys.filter(key => key.startsWith(`perm:${userId}:`));
    cache.del(userKeys);
  }

  /**
   * Limpa todo o cache de permissões
   */
  invalidateAll() {
    cache.flushAll();
  }
}

module.exports = new PermissionCache();