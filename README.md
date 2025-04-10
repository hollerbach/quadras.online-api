# Mercearia Digital API

Backend para o sistema de autenticação da Mercearia Digital, com suporte a autenticação em dois fatores, verificação de e-mail, OAuth 2.0, RBAC e todas as melhores práticas de segurança.

## Características

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

- **Arquitetura**

  - Padrão MVC
  - Separação clara de responsabilidades
  - Injeção de dependências
  - Tratamento de erros centralizado
  - Classes ES6 para organização do código

- **Documentação**

  - API documentada com Swagger/OpenAPI
  - Código bem documentado com JSDoc

- **Confiabilidade**
  - Testes automatizados
  - Validação de dados
  - Logging extensivo
  - Desligamento gracioso

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

## Configuração OAuth 2.0

Para habilitar o login com Google:

1. Acesse o [Google Cloud Console](https://console.cloud.google.com/)
2. Crie um novo projeto
3. Configure a tela de consentimento OAuth
4. Crie credenciais OAuth 2.0 (ID do cliente)
5. Adicione as origens JavaScript autorizadas (ex: http://localhost:3000)
6. Adicione URIs de redirecionamento (ex: http://localhost:3000/api/auth/google/callback)
7. Copie o ID do cliente e o segredo para as variáveis de ambiente

## Estrutura do Projeto

```
├── app.js               # Configuração do Express
├── server.js            # Ponto de entrada
├── config/              # Configurações
├── controllers/         # Controladores
├── middlewares/         # Middlewares
├── models/              # Modelos Mongoose
├── routes/              # Rotas da API
├── services/            # Serviços
├── tests/               # Testes automatizados
├── docs/                # Documentação (Swagger)
└── scripts/             # Scripts utilitários
```

## API Endpoints

| Método | Endpoint                         | Descrição                      |
| ------ | -------------------------------- | ------------------------------ |
| POST   | /api/auth/register               | Registrar novo usuário         |
| GET    | /api/auth/verify-email           | Verificar e-mail               |
| POST   | /api/auth/login                  | Login de usuário               |
| GET    | /api/auth/google                 | Iniciar login com Google       |
| GET    | /api/auth/google/callback        | Callback do login com Google   |
| POST   | /api/auth/refresh-token          | Renovar tokens                 |
| POST   | /api/auth/logout                 | Logout (invalidar tokens)      |
| POST   | /api/auth/2fa/setup              | Configurar 2FA                 |
| POST   | /api/auth/2fa/verify             | Verificar token 2FA            |
| POST   | /api/auth/2fa/disable            | Desativar 2FA                  |
| POST   | /api/auth/password-reset/request | Solicitar redefinição de senha |
| POST   | /api/auth/password-reset/confirm | Confirmar redefinição de senha |
| GET    | /api/users/profile               | Obter perfil do usuário        |
| PUT    | /api/users/profile               | Atualizar perfil               |
| PUT    | /api/users/password              | Alterar senha                  |
| GET    | /api/users                       | Listar usuários (admin)        |
| GET    | /api/users/:id                   | Obter usuário por ID (admin)   |
| PUT    | /api/users/:id                   | Atualizar usuário (admin)      |
| DELETE | /api/users/:id                   | Desativar usuário (admin)      |

## Documentação da API

A documentação completa da API está disponível em:

```
http://localhost:3000/api/docs
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

## Fluxo de Autenticação OAuth 2.0

1. O usuário acessa a rota `/api/auth/google` para iniciar o processo de login
2. O sistema redireciona para a página de login do Google
3. Após autenticação bem-sucedida, o Google redireciona para `/api/auth/google/callback`
4. O sistema:
   - Verifica se o usuário já existe (por GoogleID ou email)
   - Se não existir, cria um novo usuário
   - Se existir mas sem vínculo com Google, vincula as contas
   - Gera tokens JWT (access + refresh)
   - Redireciona para o frontend com o token de acesso
5. O frontend armazena o token e usa para requisições subsequentes

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

## Observações Importantes:

- Em produção, use segredos fortes e complexos para JWT_SECRET, APP_KEY e GOOGLE_CLIENT_SECRET. Idealmente, gere-os usando uma ferramenta de geração de strings aleatórias seguras.
- Para o MongoDB Atlas, o MONGODB_CLUSTER seria algo como cluster0.xxxx.mongodb.net.
- Para reCAPTCHA, você precisará se registrar no Google reCAPTCHA e obter suas chaves.
- Para ambiente de desenvolvimento, você pode usar o serviço Mailhog para testar emails localmente, conforme configurado no docker-compose.
- Para os valores de tempo de expiração:
  - JWT_EXPIRES_IN: Pode ser em segundos ou unidades como 60s, 15m, 2h, 1d
  - JWT_REFRESH_EXPIRES_IN: Geralmente mais longo, como 7d (7 dias)
- Para testar localmente com Docker, muitas dessas variáveis já estão configuradas no arquivo docker-compose.yml, mas para produção, certifique-se de definir todas elas de forma segura, idealmente usando um serviço de gerenciamento de segredos como AWS Secrets Manager, HashiCorp Vault ou similar.