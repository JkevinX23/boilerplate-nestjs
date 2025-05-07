# Api NestJS - Boilerplate

## Visão Geral

Este é um boilerplate para aplicações NestJS com foco em segurança e boas práticas de desenvolvimento. O projeto inclui uma configuração completa com Fastify, TypeORM, PostgreSQL, Redis, Docker e diversas técnicas de segurança.

## Tecnologias Implementadas

- **Framework Base**: NestJS
- **HTTP Adapter**: Fastify (substituindo Express)
- **Configuração**: dotenv e @nestjs/config
- **ORM**: TypeORM com PostgreSQL
- **Containerização**: Docker e Docker Compose
- **Validação e Transformação**: class-validator e class-transformer
- **Cache**: Redis via @nestjs/cache-manager
- **Segurança**:
  - Helmet (proteção de cabeçalhos HTTP)
  - CORS configurável
  - CSRF Protection
  - Rate Limiting (Throttler)
  - Validação de entrada
  - Sanitização de dados
  - Headers de segurança adicionais

## Estrutura do Projeto

```
api/
├── docker/
│   └── docker-compose.yml
├── src/
│   ├── app.module.ts
│   ├── main.ts
│   ├── common/
│   │   ├── interceptors/
│   │   ├── filters/
│   │   ├── guards/
│   │   ├── middleware/
│   │   └── decorators/
│   ├── config/
│   │   ├── cache.config.ts
│   │   ├── database.config.ts
│   │   └── security.config.ts
│   ├── modules/
│   │   └── user/ (exemplo)
│   └── shared/
├── .env.example
├── .env
└── ormconfig.ts
```

## Instalação e Configuração

### Pré-requisitos

- Node.js (v16 ou superior)
- npm (v8 ou superior)
- Docker e Docker Compose

### Instalação

1. Clone o repositório:

```bash
git clone [URL_DO_REPOSITORIO]
cd secure-nest-api
```

2. Instale as dependências:

```bash
npm install
```

3. Configure o arquivo de ambiente:

```bash
cp .env.example .env
```

> **Nota**: Edite o arquivo .env conforme necessário para seu ambiente.

4. Inicie os serviços com Docker:

```bash
npm run docker:up
```

5. Execute as migrações:

```bash
npm run migration:run
```

6. Inicie o servidor em modo de desenvolvimento:

```bash
npm run start:dev
```

## Estrutura do Código

### 1. Configuração Principal (main.ts)

O arquivo main.ts configura o adaptador Fastify e aplica as medidas de segurança globais:

- Configuração do CORS
- Proteção CSRF
- Helmet para cabeçalhos de segurança
- Validação global com class-validator

### 2. Módulo Principal (app.module.ts)

O app.module.ts importa e configura:

- ConfigModule para variáveis de ambiente
- TypeOrmModule para conexão com PostgreSQL
- CacheModule para Redis
- ThrottlerModule para rate limiting

### 3. Configurações

As configurações são separadas em arquivos específicos:

- **database.config.ts**: Configurações do banco de dados
- **security.config.ts**: Configurações de segurança (JWT, throttling, CORS)
- **cache.config.ts**: Configurações do Redis

### 4. Módulo de Usuário (Exemplo)

Um módulo de exemplo completo com:

- Entity com TypeORM
- DTO com validação
- Repository para acesso ao banco
- Service com lógica de negócio e cache
- Controller com rotas e proteção

## Comandos Disponíveis

- `npm run start:dev`: Inicia o servidor em modo de desenvolvimento
- `npm run start:debug`: Inicia o servidor em modo de debug
- `npm run start:prod`: Inicia o servidor em modo de produção
- `npm run migration:generate -- -n NomeDaMigracao`: Gera uma nova migração
- `npm run migration:run`: Executa as migrações pendentes
- `npm run migration:revert`: Reverte a última migração
- `npm run docker:up`: Inicia os contêineres Docker
- `npm run docker:down`: Para os contêineres Docker

## Técnicas de Segurança Implementadas

### Headers de Segurança (via Helmet e middleware personalizado)

- **X-Content-Type-Options**: Previne MIME-sniffing
- **X-Frame-Options**: Proteção contra clickjacking
- **X-XSS-Protection**: Proteção básica contra XSS
- **Content-Security-Policy**: Restringe fontes de conteúdo
- **Strict-Transport-Security (HSTS)**: Força conexões HTTPS
- **Referrer-Policy**: Controla informações de referência

### Proteção de Dados

- **Validação de Entrada**: Usando class-validator
- **Sanitização**: Filtragem de dados potencialmente maliciosos
- **Classe Serialização**: Exclusão automática de dados sensíveis

### Controle de Acesso

- **CORS**: Configuração granular de origens permitidas
- **CSRF Protection**: Proteção contra ataques Cross-Site Request Forgery
- **Rate Limiting**: Proteção contra ataques de força bruta

## Melhores Práticas

### Banco de Dados

- Uso de repositórios para abstração da camada de dados
- Migrações para controle de versão do banco
- SSL opcional para conexões seguras

### Cache

- Implementação em várias camadas
- TTL configurável por tipo de dado
- Invalidação automática em operações de escrita

### Código

- Estrutura modular
- Injeção de dependências
- DTOs para validação de entrada
- Entidades para mapeamento do banco

## Extensões e Personalizações

### Adicionar um Novo Módulo

1. Crie a estrutura de pastas no diretório `src/modules/`
2. Defina as entidades, DTOs, serviços e controladores
3. Importe o módulo em `app.module.ts`

### Configurar Autenticação JWT

O boilerplate inclui as dependências para JWT, mas a implementação deve ser personalizada:

1. Configure o serviço JWT no módulo de autenticação
2. Crie guards para proteção de rotas
3. Implemente estratégias de refresh token

### Adicionar Novas Configurações

1. Crie um novo arquivo em `src/config/`
2. Use `registerAs` para definir o namespace
3. Adicione o arquivo à lista de configurações em `app.module.ts`

## Considerações de Produção

### Segurança Adicional

- Usar HTTPS em produção
- Configurar políticas de senha fortes
- Implementar autenticação multi-fator
- Configurar logs de auditoria

### Performance

- Ajustar configurações de cache
- Otimizar consultas ao banco de dados
- Configurar índices apropriados
- Implementar estratégias de paginação

### Monitoramento

- Adicionar logging estruturado
- Implementar health checks
- Configurar monitoramento de performance
