# Usar versão específica do Node.js para consistência
FROM node:22-alpine

# Definir diretório de trabalho
WORKDIR /app

# Argumentos de build para configuração do ambiente
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

# Instalar dependências globais (principalmente de segurança)
RUN apk --no-cache add dumb-init

# Copiar arquivos de configuração
COPY package*.json ./

# Instalar dependências com flags para segurança e produção
RUN npm ci --only=production && npm cache clean --force

# Copiar código-fonte
COPY . .

# Usuário não-root para segurança
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app
USER nodejs

# Exposição de porta
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/health || exit 1

# Comando para iniciar aplicação com dumb-init para manipular sinais corretamente
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
