-- Esquema para o sistema de Agendamento de Quadras
-- Arquivo: infrastructure/database/mysql/migrations/01_initial_schema.sql

-- Configuração do banco de dados
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Tabela de Usuários
CREATE TABLE IF NOT EXISTS `users` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `role` ENUM('user', 'admin') DEFAULT 'user',
  `verified` BOOLEAN DEFAULT FALSE,
  `active` BOOLEAN DEFAULT TRUE,
  `verify_token` VARCHAR(255) NULL,
  `verify_token_expires` DATETIME NULL,
  `reset_token` VARCHAR(255) NULL,
  `reset_token_expires` DATETIME NULL,
  `two_factor_enabled` BOOLEAN DEFAULT FALSE,
  `two_factor_secret` VARCHAR(255) NULL,
  `name` VARCHAR(100) NULL,
  `surname` VARCHAR(100) NULL,
  `last_login` DATETIME NULL,
  `failed_login_attempts` INT DEFAULT 0,
  `lock_until` DATETIME NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_users_email` (`email`),
  INDEX `idx_users_verify_token` (`verify_token`),
  INDEX `idx_users_reset_token` (`reset_token`),
  INDEX `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar códigos de recuperação 2FA
CREATE TABLE IF NOT EXISTS `user_recovery_codes` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `user_id` VARCHAR(36) NOT NULL,
  `code` VARCHAR(20) NOT NULL,
  `used` BOOLEAN DEFAULT FALSE,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  INDEX `idx_recovery_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar informações oauth
CREATE TABLE IF NOT EXISTS `user_oauth` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `user_id` VARCHAR(36) NOT NULL,
  `provider` VARCHAR(50) NOT NULL,
  `provider_id` VARCHAR(255) NOT NULL,
  `provider_email` VARCHAR(255) NULL,
  `provider_name` VARCHAR(255) NULL,
  `provider_picture` TEXT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  UNIQUE KEY `unique_user_provider` (`user_id`, `provider`),
  INDEX `idx_provider_id` (`provider_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela RBAC - Permissões
CREATE TABLE IF NOT EXISTS `permissions` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `code` VARCHAR(100) NOT NULL UNIQUE,
  `description` TEXT NOT NULL,
  `category` ENUM('user', 'product', 'order', 'delivery', 'report', 'system') NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_permissions_code` (`code`),
  INDEX `idx_permissions_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela RBAC - Recursos
CREATE TABLE IF NOT EXISTS `resources` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `description` TEXT NOT NULL,
  `type` ENUM('route', 'entity', 'feature', 'report', 'menu') NOT NULL,
  `path` VARCHAR(255) NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_resources_type` (`type`),
  INDEX `idx_resources_path` (`path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela RBAC - Papéis (Roles)
CREATE TABLE IF NOT EXISTS `roles` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL UNIQUE,
  `description` TEXT NOT NULL,
  `is_system` BOOLEAN DEFAULT FALSE,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_roles_is_system` (`is_system`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para relacionamento entre Papéis e Permissões
CREATE TABLE IF NOT EXISTS `role_permissions` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `role_id` VARCHAR(36) NOT NULL,
  `permission_id` VARCHAR(36) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE,
  UNIQUE KEY `unique_role_permission` (`role_id`, `permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para recursos associados a permissões de papéis
CREATE TABLE IF NOT EXISTS `role_permission_resources` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `role_permission_id` VARCHAR(36) NOT NULL,
  `resource_id` VARCHAR(36) NOT NULL,
  `conditions` JSON NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`role_permission_id`) REFERENCES `role_permissions` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`resource_id`) REFERENCES `resources` (`id`) ON DELETE CASCADE,
  UNIQUE KEY `unique_role_perm_resource` (`role_permission_id`, `resource_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de atribuição de papéis aos usuários
CREATE TABLE IF NOT EXISTS `user_roles` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `user_id` VARCHAR(36) NOT NULL,
  `role_id` VARCHAR(36) NOT NULL,
  `assigned_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `assigned_by` VARCHAR(36) NULL,
  `scope` ENUM('global', 'store', 'department') DEFAULT 'global',
  `scope_id` VARCHAR(36) NULL,
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`assigned_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  UNIQUE KEY `unique_user_role_scope` (`user_id`, `role_id`, `scope`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de tokens de atualização (refresh tokens)
CREATE TABLE IF NOT EXISTS `refresh_tokens` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `token` VARCHAR(255) NOT NULL UNIQUE,
  `user_id` VARCHAR(36) NOT NULL,
  `user_email` VARCHAR(255) NOT NULL,
  `expires` DATETIME NOT NULL,
  `revoked` BOOLEAN DEFAULT FALSE,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by_ip` VARCHAR(50) NULL,
  `revoked_at` DATETIME NULL,
  `revoked_by_ip` VARCHAR(50) NULL,
  `replaced_by_token` VARCHAR(255) NULL,
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  INDEX `idx_token` (`token`),
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de blacklist de tokens
CREATE TABLE IF NOT EXISTS `token_blacklist` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `token` VARCHAR(255) NOT NULL,
  `type` ENUM('access', 'refresh') NOT NULL,
  `expires` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_token` (`token`),
  INDEX `idx_expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de logs de auditoria
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `action` VARCHAR(100) NOT NULL,
  `user_id` VARCHAR(36) NULL,
  `user_email` VARCHAR(255) NULL,
  `ip_address` VARCHAR(50) NULL,
  `details` JSON NULL,
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_action` (`action`),
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de tentativas de login
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `user_id` VARCHAR(36) NULL,
  `email` VARCHAR(255) NOT NULL,
  `success` BOOLEAN DEFAULT FALSE,
  `ip_address` VARCHAR(50) NULL,
  `details` JSON NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_email` (`email`),
  INDEX `idx_ip_address` (`ip_address`),
  INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Restore foreign key checks
SET FOREIGN_KEY_CHECKS = 1;