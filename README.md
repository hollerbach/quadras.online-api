# Mercearia Digital API

Backend para o sistema da Mercearia Digital, implementado com arquitetura limpa (Clean Architecture) e Domain-Driven Design (DDD), com suporte a autenticação em dois fatores, verificação de e-mail, OAuth 2.0, RBAC e todas as melhores práticas de segurança.

## Características

- **Arquitetura Limpa (Clean Architecture)**
  - Separação clara entre domínios funcionais
  - Independência de frameworks
  - Camadas bem definidas: Domain, Application, Infrastructure, Interfaces
  - Fácil adição de novos domínios funcionais

- **Autenticação Segura**
  - JWT (Access Token + Refresh Token)
  - Autenticação em Dois Fatores (2FA) com TOTP
  - OAuth 2.0 com Google
  - Rate limiting para proteção contra ataques de força bruta
  - Verificação de e-mail
  - Redefinição de senha segura

- **Segurança**
  - Proteção contra CSRF
  - Configurações de segurança com Helmet (CSP, XSS, etc.)
  - Blacklist de tokens
  - Proteção CORS configurável
  - Validação de entrada rigorosa

- **Design Patterns**
  - Repository Pattern
  - Use Case Pattern
  - Dependency Injection
  - Factory Pattern
  - Adapter Pattern

- **Domínios**
  - Autenticação (implementado)
  - Usuários (implementado)
  - Produtos (estrutura preparada)
  - Pedidos (estrutura preparada)
  - Entregas (estrutura preparada)

- **Confiabilidade**
  - Testes automatizados
  - Validação de dados
  - Logging extensivo
  - Desligamento gracioso

## Estrutura do Projeto

```
/src
  /domain                 # Regras de negócio e entidades
    /auth                 # Domínio de autenticação
      /entities           # Modelos de domínio
      /repositories       # Interfaces para acesso a dados
      /use-cases          # Casos de uso do domínio
      /services           # Serviços específicos do domínio
    /users                # Domínio de usuários
      /entities
      /repositories
      /use-cases
      /services
    /products             # (Futuro domínio)
    /orders               # (Futuro domínio)
    /delivery             # (Futuro domínio)
  
  /application            # Orquestração entre domínios
    /services             # Serviços que coordenam múltiplos domínios
    /dtos                 # Objetos de transferência de dados
    /interfaces           # Interfaces da aplicação
    /events               # Sistema de eventos entre domínios
  
  /infrastructure         # Detalhes técnicos e implementações
    /database             # Implementação do acesso a dados
      /mongodb            # Implementação específica para MongoDB
        /models           # Modelos Mongoose
        /repositories     # Implementações concretas dos repositórios
    /external             # Serviços externos
      /mail               # Serviço de e-mail
      /oauth              # Serviços OAuth (Google, etc.)
    /security             # Implementações de segurança
      /token              # Serviço de tokens
      /password           # Serviço de hashing de senhas
      /two-factor         # Serviço de autenticação em dois fatores
    /logging              # Serviço de logging
    /config               # Configurações da aplicação
  
  /interfaces             # Adaptadores para o mundo externo
    /api                  # API REST
      /controllers        # Controladores HTTP
      /routes             # Definições de rotas
      /middlewares        # Middlewares da API
      /validators         # Validação de entrada
      /presenters         # Transformação de saída
    /jobs                 # Tarefas agendadas
    /subscribers          # Assinantes de eventos

  /shared                 # Utilitários e código compartilhado
    /utils                # Funções utilitárias
    /constants            # Constantes e enumerações
    /errors               # Classes de erro personalizadas

  /app.js                 # Configuração da aplicação
  /server.js              # Ponto de entrada
```

## Requisitos

- Node.js 16+
- MongoDB 4.4+
- NPM ou Yarn

## Instalação

### Usando Docker (recomendado)

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/mercado-digital-api.git
cd mercado-digital-api

# Configurar variáveis de ambiente
cp .env.example .env

# Iniciar com Docker Compose
npm run docker:dev
```

### Instalação manual

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/mercado-digital-api.git
cd mercado-digital-api

# Instalar dependências
npm install

# Configurar variáveis de ambiente
cp .env.example .env

# Iniciar em desenvolvimento
npm run dev

# Iniciar em produção
npm start
```

## Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```
# Ambiente
NODE_ENV=development
PORT=3000
BASE_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173

# JWT
JWT_SECRET=seu_jwt_secret_seguro
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# MongoDB
MONGODB_CLUSTER=seu_cluster_mongodb
DB_USER=seu_usuario_db
DB_PASS=sua_senha_db
DB_NAME=mercearia_digital
MONGODB_APP=mercearia_digital

# Email
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=seu_email@example.com
EMAIL_PASS=sua_senha_email

# Segurança
APP_KEY=sua_chave_app_segura
RECAPTCHA_SECRET=seu_recaptcha_secret
ALLOWED_ORIGINS=https://mercearia.digital,http://localhost:5173

# OAuth
GOOGLE_CLIENT_ID=seu_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=seu_google_client_secret
```

## API Endpoints

| Método | Endpoint                          | Descrição                      |
| ------ | --------------------------------- | ------------------------------ |
| POST   | /api/auth/register                | Registrar novo usuário         |
| GET    | /api/auth/verify-email            | Verificar e-mail               |
| POST   | /api/auth/login                   | Login de usuário               |
| GET    | /api/auth/google                  | Iniciar login com Google       |
| GET    | /api/auth/google/callback         | Callback do login com Google   |
| POST   | /api/auth/refresh-token           | Renovar tokens                 |
| POST   | /api/auth/logout                  | Logout (invalidar tokens)      |
| POST   | /api/auth/2fa/setup               | Configurar 2FA                 |
| POST   | /api/auth/2fa/verify              | Verificar token 2FA            |
| POST   | /api/auth/2fa/disable             | Desativar 2FA                  |
| POST   | /api/auth/password-reset/request  | Solicitar redefinição de senha |
| POST   | /api/auth/password-reset/confirm  | Confirmar redefinição de senha |
| GET    | /api/users/profile                | Obter perfil do usuário        |
| PUT    | /api/users/profile                | Atualizar perfil               |
| PUT    | /api/users/password               | Alterar senha                  |
| GET    | /api/users                        | Listar usuários (admin)        |
| GET    | /api/users/:id                    | Obter usuário por ID (admin)   |
| PUT    | /api/users/:id                    | Atualizar usuário (admin)      |
| DELETE | /api/users/:id                    | Desativar usuário (admin)      |

## Documentação da API

A documentação completa da API está disponível em:

```
http://localhost:3000/docs
```

## Testes

```bash
# Executar todos os testes
npm test

# Executar testes com coverage
npm run test:coverage

# Executar testes em modo watch
npm run test:watch
```

## Linting e Formatação

```bash
# Verificar erros de linting
npm run lint

# Corrigir erros de linting automaticamente
npm run lint:fix

# Formatar código com Prettier
npm run format
```

## Docker

```bash
# Iniciar ambiente de desenvolvimento com Docker Compose
npm run docker:dev

# Construir imagem Docker
npm run docker:build
```

## Adicionando Novos Domínios

Para adicionar um novo domínio funcional (como produtos, pedidos, etc.):

1. Crie a estrutura de pastas para o domínio em `/src/domain/[nome-do-domínio]/`
2. Defina entidades na pasta `entities` e interfaces de repositório em `repositories`
3. Implemente casos de uso específicos em `use-cases`
4. Crie implementações do repositório em `/src/infrastructure/database/mongodb/repositories/`
5. Desenvolva controllers, validadores e rotas para a API

## Fluxo Completo de Aplicação

1. A requisição HTTP chega através de um router (`/interfaces/api/routes`)
2. É processada por middlewares (`/interfaces/api/middlewares`)
3. O controller (`/interfaces/api/controllers`) recebe a requisição
4. Os dados são validados (`/interfaces/api/validators`)
5. O controller chama um caso de uso (`/domain/*/use-cases`)
6. O caso de uso implementa a lógica de negócio usando repositórios
7. Os repositórios (`/domain/*/repositories`) são interfaces implementadas na infraestrutura
8. O resultado volta pelo mesmo caminho, transformado pelo controller
9. A resposta HTTP é enviada ao cliente

## Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Implemente suas alterações
4. Execute os testes (`npm test`)
5. Commit suas alterações (`git commit -am 'Adiciona nova feature'`)
6. Push para a branch (`git push origin feature/nova-feature`)
7. Abra um Pull Request

## Licença

Este projeto está licenciado sob a [Licença ISC](LICENSE).


Todos os endpoints originais continuam funcionando, porém agora são processados através das camadas bem definidas da arquitetura limpa:

Routes → Controllers → Use Cases → Repositories
Controllers chamam casos de uso em vez de serviços diretamente
Os casos de uso encapsulam a lógica de negócio e usam repositórios para persistência

A API está pronta para produção e mantém a paridade funcional com o código original do GitHub, apenas com uma arquitetura mais robusta e sustentável.


# Melhorias de Segurança Implementadas

Este documento descreve as melhorias de segurança implementadas na API, focando em headers de segurança robustos, Content Security Policy (CSP) e cookies seguros.

## 1. Headers de Segurança Aprimorados

### Implementações:

- **Content Security Policy (CSP)**: Configuração restritiva que limita origens para scripts, conexões, estilos e outros recursos
- **HTTP Strict Transport Security (HSTS)**: Força uso de HTTPS por 1 ano
- **X-Content-Type-Options**: Impede "MIME type sniffing"
- **X-Frame-Options**: Bloqueia carregamento da aplicação em frames/iframes
- **Referrer-Policy**: Controla informações de referência enviadas em requisições
- **Origin-Agent-Cluster**: Agrupa contextos de agente com base em origem
- **Cross-Origin-Resource-Policy**: Controla quais sites podem carregar recursos da API
- **Cross-Origin-Opener-Policy**: Isola o contexto de navegação para melhorar segurança
- **Permissions-Policy**: Restringe uso de APIs sensíveis do navegador
- **X-XSS-Protection**: Camada de proteção adicional contra XSS
- **Cache-Control**: Previne armazenamento em cache de respostas sensíveis

### Arquivos Alterados:
- `src/infrastructure/security/security.config.js` (configuração central)
- `src/interfaces/api/middlewares/index.js` (aplicação dos headers)

## 2. Configuração de Cookies Seguros

### Implementações:

- **HttpOnly**: Impede acesso aos cookies via JavaScript
- **Secure**: Garante transmissão apenas via HTTPS
- **SameSite=Strict**: Previne ataques CSRF
- **Path Restrictions**: Restringe cookies para caminhos específicos
- **Cookies Temporários**: Configuração para cookies de sessão

### Arquivos Alterados:
- `src/infrastructure/security/security.config.js` (definição de políticas de cookie)
- `src/interfaces/api/controllers/auth.controller.js` (aplicação nos endpoints relevantes)

## 3. Proteções Adicionais

### Implementações:

- **Rate Limiting**: Limite de requisições por IP
- **Speed Limiting**: Atraso progressivo para desestimular brute force
- **Sanitização de Parâmetros**: Proteção contra Parameter Pollution
- **Limitação de Tamanho de Payload**: Prevenção contra ataques DoS
- **Métodos HTTP Restritos**: Apenas métodos necessários são permitidos

### Arquivos Alterados:
- `src/interfaces/api/middlewares/index.js`

## Como Usar as Novas Configurações de Segurança

### Para Adicionar Cookies Seguros:

```javascript
// Importar configurações de segurança
const securityConfig = require('../../../infrastructure/security/security.config');

// Usar em respostas que criam cookies
res.cookie('nomeDoCookie', valor, securityConfig.cookieOptions.sensitive);

// Para cookies menos sensíveis
res.cookie('preferencias', valor, securityConfig.cookieOptions.standard);
```

### Considerações para Frontend:

Quando implementar o frontend para esta API, considere:

1. A política CSP restritiva pode exigir ajustes para compatibilidade com frameworks e bibliotecas
2. Os cookies HttpOnly não serão acessíveis via JavaScript
3. Com SameSite=Strict, requisições cross-site não incluirão cookies automaticamente

## Próximos Passos

Para fortalecer ainda mais a segurança, considere:

1. Implementar validação de entrada mais rigorosa em todos os endpoints
2. Migrar para autenticação JWT com assinaturas assímétricas (RS256)
3. Implementar auditoria e logging mais detalhados
4. Adicionar monitoramento para detecção de anomalias

## Referências

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Content Security Policy (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Cookie Security (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)