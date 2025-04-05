// controllers/user.controller.js
const userService = require('../services/user.service');
const logger = require('../services/logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');

class UserController {
  /**
   * Obtém o perfil do usuário atual
   */
  async getProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const user = await userService.findById(userId);

      if (!user) {
        throw new ApiError(404, 'Usuário não encontrado');
      }

      // Retornar usuário sem dados sensíveis
      const userProfile = userService.sanitizeUser(user);
      res.status(200).json(userProfile);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Atualiza o perfil do usuário atual
   */
  async updateProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const updates = req.body;

      // Não permitir atualização de campos sensíveis
      delete updates.password;
      delete updates.role;
      delete updates.verified;
      delete updates.twoFactorEnabled;
      delete updates.twoFactorSecret;

      const updatedUser = await userService.updateUser(userId, updates);
      const userProfile = userService.sanitizeUser(updatedUser);

      logger.info(`Perfil atualizado: ${updatedUser.email}`);
      res.status(200).json(userProfile);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Altera a senha do usuário atual
   */
  async changePassword(req, res, next) {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;

      await userService.changePassword(userId, currentPassword, newPassword);

      logger.info(`Senha alterada: ${req.user.email}`);
      res.status(200).json({ message: 'Senha alterada com sucesso' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Lista todos os usuários (somente admin)
   */
  async getAllUsers(req, res, next) {
    try {
      const { page = 1, limit = 20, sort = 'email', order = 'asc', search } = req.query;

      const options = {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        sort: sort,
        order: order,
        search: search
      };

      const result = await userService.findAllUsers(options);

      res.status(200).json({
        users: result.users.map(user => userService.sanitizeUser(user)),
        pagination: {
          total: result.total,
          page: result.page,
          pages: result.pages,
          limit: result.limit
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Obtém um usuário por ID (somente admin)
   */
  async getUserById(req, res, next) {
    try {
      const { id } = req.params;
      const user = await userService.findById(id);

      if (!user) {
        throw new ApiError(404, 'Usuário não encontrado');
      }

      const userDetails = userService.sanitizeUser(user, true); // true = incluir dados adicionais para admin
      res.status(200).json(userDetails);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Atualiza um usuário por ID (somente admin)
   */
  async updateUser(req, res, next) {
    try {
      const { id } = req.params;
      const updates = req.body;

      // Não permitir atualização de campos muito sensíveis
      delete updates.password;
      delete updates.twoFactorSecret;

      const updatedUser = await userService.adminUpdateUser(id, updates);
      const userDetails = userService.sanitizeUser(updatedUser, true);

      logger.info(`Usuário atualizado pelo admin: ${updatedUser.email}`);
      res.status(200).json(userDetails);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Desativa um usuário (não exclui)
   */
  async deactivateUser(req, res, next) {
    try {
      const { id } = req.params;

      // Verificar se não está tentando desativar a si mesmo
      if (id === req.user.id) {
        throw new ApiError(400, 'Não é possível desativar seu próprio usuário');
      }

      await userService.deactivateUser(id);

      logger.info(`Usuário desativado pelo admin: ${id}`);
      res.status(200).json({ message: 'Usuário desativado com sucesso' });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new UserController();
