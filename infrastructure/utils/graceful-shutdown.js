// src/infrastructure/utils/graceful-shutdown.js
const logger = require('../logging/logger');
const { closeConnection } = require('../database/mongodb/connection');

/**
 * Gerencia o desligamento gracioso da aplicação
 * para garantir que recursos sejam liberados corretamente
 */
class GracefulShutdown {
  constructor() {
    this.server = null;
    this.isShuttingDown = false;
    this.waitTimeMs = 30000; // 30 segundos de timeout para desligamento forçado
    this.connectionTracking = {
      connections: 0,
      activeRequests: new Map()
    };
  }
  
  /**
   * Configura o gerenciamento de desligamento para um servidor HTTP
   * @param {http.Server} server Servidor HTTP a ser gerenciado
   */
  registerServer(server) {
    this.server = server;
    
    // Rastrear conexões
    server.on('connection', (connection) => {
      // Gerar ID único para a conexão
      const connectionId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
      
      // Armazenar informações
      this.connectionTracking.connections++;
      
      // Registrar encerramento da conexão
      connection.on('close', () => {
        this.connectionTracking.connections--;
      });
      
      // Evitar que a conexão fique aberta indefinidamente durante o desligamento
      if (this.isShuttingDown) {
        connection.end();
      }
    });
    
    // Configurar handlers para sinais de término
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));
    process.on('SIGINT', () => this.shutdown('SIGINT'));
    
    logger.info('Gerenciamento de desligamento gracioso configurado');
    return this;
  }
  
  /**
   * Registra o início de uma requisição HTTP
   * @param {Request} req Objeto da requisição HTTP
   * @param {Response} res Objeto da resposta HTTP
   */
  trackRequest(req, res) {
    if (this.isShuttingDown) {
      // Se estiver em processo de desligamento, não aceitar novas requisições
      res.set('Connection', 'close');
      res.status(503).send('Serviço indisponível, servidor em processo de desligamento');
      return false;
    }
    
    // Criar ID único para a requisição
    const requestId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    
    // Registrar a requisição
    this.connectionTracking.activeRequests.set(requestId, {
      url: req.url,
      method: req.method,
      ip: req.ip,
      startTime: Date.now()
    });
    
    // Quando a resposta for concluída, remover do rastreamento
    res.on('finish', () => {
      this.connectionTracking.activeRequests.delete(requestId);
    });
    
    return true;
  }
  
  /**
   * Realiza o desligamento gracioso da aplicação
   * @param {string} signal Sinal que iniciou o desligamento
   */
  async shutdown(signal) {
    if (this.isShuttingDown) {
      return;
    }
    
    this.isShuttingDown = true;
    logger.info(`Iniciando desligamento gracioso (sinal: ${signal})`);
    
    // Definir timeout para forçar encerramento se necessário
    const forcedShutdownTimeout = setTimeout(() => {
      logger.error('Tempo limite para desligamento excedido. Forçando encerramento.');
      process.exit(1);
    }, this.waitTimeMs);
    
    try {
      // 1. Parar de aceitar novas requisições (mas continuar processando as atuais)
      if (this.server) {
        logger.info('Parando de aceitar novas conexões...');
        this.server.close(() => {
          logger.info('Servidor HTTP fechado com sucesso');
        });
      }
      
      // 2. Registrar estatísticas atuais
      logger.info(`Requisições ativas: ${this.connectionTracking.activeRequests.size}`);
      logger.info(`Conexões abertas: ${this.connectionTracking.connections}`);
      
      // 3. Aguardar requisições ativas terminarem (com timeout)
      if (this.connectionTracking.activeRequests.size > 0) {
        logger.info('Aguardando requisições ativas terminarem...');
        
        // Esperar até que todas as requisições sejam concluídas ou timeout
        await new Promise(resolve => {
          const checkInterval = setInterval(() => {
            if (this.connectionTracking.activeRequests.size === 0) {
              clearInterval(checkInterval);
              resolve();
            }
          }, 1000);
        });
      }
      
      // 4. Fechar conexões com o banco de dados
      logger.info('Fechando conexão com o banco de dados...');
      await closeConnection();
      
      // 5. Liberar outros recursos
      logger.info('Liberando recursos adicionais...');
      // Adicionar aqui código para liberar outros recursos (filas, cache, etc.)
      
      // Desligar com sucesso
      clearTimeout(forcedShutdownTimeout);
      logger.info('Desligamento gracioso concluído com sucesso');
      process.exit(0);
    } catch (error) {
      logger.error(`Erro durante o desligamento: ${error.message}`);
      process.exit(1);
    }
  }
}

module.exports = new GracefulShutdown();