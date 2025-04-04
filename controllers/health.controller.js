// Implementar um novo controlador: controllers/health.controller.js
const mongoose = require('mongoose');
const logger = require('../services/logger');
const mailService = require('../services/mail.service');

class HealthController {
  async checkHealth(req, res) {
    const healthStatus = {
      status: 'UP',
      timestamp: new Date().toISOString(),
      components: {
        api: { status: 'UP' },
        database: { status: 'UNKNOWN' },
        email: { status: 'UNKNOWN' },
        cache: { status: 'UNKNOWN' }
      },
      details: {
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      }
    };
    
    // Verificar MongoDB
    try {
      const dbState = mongoose.connection.readyState;
      healthStatus.components.database = {
        status: dbState === 1 ? 'UP' : 'DOWN',
        details: {
          state: dbState,
          stateDesc: ['disconnected', 'connected', 'connecting', 'disconnecting'][dbState] || 'unknown'
        }
      };
    } catch (err) {
      healthStatus.components.database = {
        status: 'DOWN',
        error: err.message
      };
    }
    
    // Verificar servidor de email (opcional)
    try {
      const emailCheck = await new Promise((resolve, reject) => {
        mailService.transporter.verify((error) => {
          if (error) reject(error);
          else resolve(true);
        });
      });
      
      healthStatus.components.email = {
        status: emailCheck ? 'UP' : 'DOWN'
      };
    } catch (err) {
      healthStatus.components.email = {
        status: 'DOWN',
        error: err.message
      };
    }
    
    // Verificar cache se implementado
    if (typeof cacheService !== 'undefined') {
      try {
        await cacheService.set('health-check', 'ok', 5);
        const testValue = await cacheService.get('health-check');
        
        healthStatus.components.cache = {
          status: testValue === 'ok' ? 'UP' : 'DOWN'
        };
      } catch (err) {
        healthStatus.components.cache = {
          status: 'DOWN',
          error: err.message
        };
      }
    }
    
    // Determinar status geral
    const criticalComponents = ['database'];
    const anyDownCritical = criticalComponents.some(
      component => healthStatus.components[component]?.status === 'DOWN'
    );
    
    if (anyDownCritical) {
      healthStatus.status = 'DOWN';
      res.status(503);
    } else {
      res.status(200);
    }
    
    res.json(healthStatus);
  }
}

module.exports = new HealthController();