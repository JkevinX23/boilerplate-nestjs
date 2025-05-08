# Api NestJS - Boilerplate

## Visão Geral

Este é um boilerplate para aplicações NestJS com foco em segurança e boas práticas de desenvolvimento. O projeto inclui uma configuração completa com Fastify, TypeORM, PostgreSQL, Redis, Docker, um robusto sistema de Autorização baseado em Papéis (Role-Based Access Control - RBAC) utilizando CASL, e diversas outras técnicas de segurança.

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
  - CSRF Protection (@fastify/csrf-protection)
  - Rate Limiting (Throttler)
  - Validação de entrada
  - Sanitização de dados (implícita via ORM e validação)
  - Headers de segurança adicionais
- **Autorização**: CASL (@casl/ability) para controle de acesso baseado em papéis e permissões granulares.
- **Email**: Sistema de envio de emails via SMTP utilizando Nodemailer e templates Handlebars.

## Estrutura do Projeto

```
api/
├── docker/
│   └── docker-compose.yml
├── src/
│   ├── app.module.ts
│   ├── main.ts
│   ├── data-source.ts        # Configuração do TypeORM para CLI e runtime
│   ├── common/
│   │   ├── interceptors/
│   │   ├── filters/
│   │   ├── guards/
│   │   ├── middleware/
│   │   └── decorators/
│   ├── config/
│   │   ├── cache.config.ts
│   │   ├── database.config.ts
│   │   ├── security.config.ts
│   │   └── email.config.ts
│   ├── modules/
│   │   ├── user/
│   │   │   ├── user.entity.ts
│   │   │   └── ...
│   │   ├── auth/             # Módulo de Autenticação (JWT)
│   │   ├── authorization/    # Módulo de Autorização com CASL
│   │   └── email/            # Módulo de envio de emails via SMTP
│   │       ├── templates/    # Templates HTML para emails
│   │       ├── interfaces/   # Interfaces para tipagem
│   │       ├── email.service.ts
│   │       └── email.module.ts
│   │       ├── casl/
│   │       │   └── casl-ability.factory.ts
│   │       ├── decorators/
│   │       │   └── check-policies.decorator.ts
│   │       ├── entities/
│   │       │   └── role.entity.ts
│   │       ├── guards/
│   │       │   └── policies.guard.ts
│   │       └── authorization.module.ts
│   └── shared/                
│   └── migrations/           
├── .env.example
├── .env
└── package.json
```

> **Nota**: O arquivo `ormconfig.ts` pode ter sido substituído por `data-source.ts` para compatibilidade com versões mais recentes do TypeORM e para a CLI.

## Instalação e Configuração

### Pré-requisitos

- Node.js (v16 ou superior recomendado)
- Yarn (ou npm)
- Docker e Docker Compose

### Instalação

1.  Clone o repositório:

    ```bash
    git clone [URL_DO_REPOSITORIO]
    cd api # Navegue para o diretório da API
    ```

2.  Instale as dependências:

    ```bash
    yarn install
    # ou
    # npm install
    ```

3.  Configure o arquivo de ambiente:
    Crie um arquivo `.env.development` (ou `.env` se preferir) na raiz do diretório `api/`, baseando-se no `.env.example` (se existir) ou configurando as seguintes variáveis:

    ```env
    # Configurações do Banco de Dados
    DB_HOST=localhost
    DB_PORT=5432
    DB_USERNAME=postgres
    DB_PASSWORD=postgres
    DB_DATABASE=nest_db
    DB_SYNCHRONIZE=false # Deve ser false em produção e ao usar migrations
    DB_LOGGING=true
    DB_SSL=false

    # Configurações do Redis
    REDIS_HOST=localhost
    REDIS_PORT=6379
    REDIS_TTL=60

    # Configurações da Aplicação
    PORT=3000
    NODE_ENV=development
    CORS_ORIGIN=* # Seja mais restritivo em produção

    # JWT Secrets (se estiver usando o módulo de autenticação)
    # JWT_SECRET=yourSecretKeyForAccessToken
    # JWT_REFRESH_SECRET=yourSecretKeyForRefreshToken
    # JWT_ACCESS_TOKEN_EXPIRATION_TIME=3600 # 1 hora (ex: 15m para 15 minutos)
    # JWT_REFRESH_TOKEN_EXPIRATION_TIME=86400 # 1 dia (ex: 7d para 7 dias)

    # Configurações de Rate Limiting para Falhas de Login (Opcional, padrões existem)
    # FAILED_LOGIN_MAX_ATTEMPTS=5
    # FAILED_LOGIN_WINDOW_SECONDS=300
    # FAILED_LOGIN_BLOCK_SECONDS=900
    
    # Configurações do Servidor SMTP
    # EMAIL_HOST=smtp.example.com
    # EMAIL_PORT=587
    # EMAIL_SECURE=false
    # EMAIL_USER=user@example.com
    # EMAIL_PASSWORD=your_password
    # EMAIL_FROM="Boilerplate <noreply@boilerplate.com>"
    ```

4.  Inicie os serviços com Docker (PostgreSQL, Redis):

    ```bash
    docker-compose -f ./docker/docker-compose.yml up -d
    ```

    Ou, se tiver um script no `package.json`:

    ```bash
    yarn docker:up
    # ou
    # npm run docker:up
    ```

5.  Execute as migrações do TypeORM:
    Certifique-se que o arquivo `api/src/data-source.ts` está configurado corretamente para a CLI.

    ```bash
    yarn typeorm migration:run -d ./src/data-source.ts
    # ou
    # npm run typeorm -- migration:run -d ./src/data-source.ts
    ```

    (Verifique os scripts no seu `package.json` para os comandos exatos de migração).

6.  Inicie o servidor em modo de desenvolvimento:
    ```bash
    yarn start:dev
    # ou
    # npm run start:dev
    ```

A API estará rodando em `http://localhost:3000` (ou a porta configurada).

## Estrutura do Código

### 1. Configuração Principal (`main.ts`)

O arquivo `main.ts` configura o adaptador Fastify e aplica middlewares e configurações globais:

- Logger customizado
- Configuração do CORS via `@fastify/cors`
- Proteção CSRF com `@fastify/csrf-protection`
- Compressão com `@fastify/compress`
- Helmet para cabeçalhos de segurança
- Versionamento de API via Header (`X-API-Version`)
- `ValidationPipe` global para validação e transformação automática de DTOs.

### 2. Módulo Principal (`app.module.ts`)

O `app.module.ts` é o módulo raiz que importa e configura:

- `ConfigModule`: Para gerenciamento de variáveis de ambiente e configurações customizadas.
- `TypeOrmModule`: Para integração com o PostgreSQL.
- `CacheModule`: Para integração com Redis.
- `ThrottlerModule`: Para rate limiting.
- Módulos de funcionalidades da aplicação, como `UserModule`, `AuthModule`, e o novo `AuthorizationModule`.

### 3. Configurações (`src/config/`)

Configurações específicas são modularizadas:

- `database.config.ts`: Configurações de conexão com o banco de dados.
- `security.config.ts`: Pode conter configurações para JWT, throttling, CORS (embora CORS esteja em `main.ts`).
- `cache.config.ts`: Configurações para o Redis (host, port, TTL).

### 4. Autorização com CASL (`src/modules/authorization/`)

O sistema de autorização utiliza CASL para um controle de acesso fino e baseado em papéis.

#### Componentes Chave:

- **`Role` Entity (`entities/role.entity.ts`)**:

  - Armazena o nome do papel (ex: `admin`, `operator`, `viewer`).
  - Contém um campo `permissions` (JSONB) que armazena um array de objetos `CaslPermission`.

- **`CaslPermission` Interface**:
  Define a estrutura de uma permissão:

  ```typescript
  interface CaslPermission {
    action: string; // Ex: 'manage', 'read', 'create', 'update', 'delete'
    subject: string; // Ex: 'all', 'User', 'Article' (nome da entidade ou 'all')
    conditions?: any; // Opcional: condições específicas para a permissão (formato CASL)
    fields?: string[]; // Opcional: campos específicos da entidade aos quais a permissão se aplica
  }
  ```

- **`User` Entity (`src/modules/user/user.entity.ts`)**:

  - Possui uma relação `ManyToMany` com a entidade `Role`. Um usuário pode ter múltiplos papéis. Os papéis são carregados ansiosamente (`eager: true`).

- **`CaslAbilityFactory` (`casl/casl-ability.factory.ts`)**:

  - Serviço responsável por construir o objeto `AppAbility` (uma instância de `Ability` do CASL) para o usuário autenticado.
  - Ele lê os papéis do usuário e as `CaslPermission` associadas a cada papel.
  - Utiliza um `subjectConstructorMap` para mapear nomes de `subject` (strings) para as classes de entidade reais (ex: `'User'` -> `User` class). Isso é crucial para o CASL entender sobre qual tipo de objeto a permissão se aplica.
  - Define o enum `Action` com as ações possíveis (`Manage`, `Create`, `Read`, `Update`, `Delete`).
  - Define o tipo `Subjects` que infere os sujeitos possíveis a partir das classes de entidade e a string `'all'`.

- **`AuthorizationModule` (`authorization.module.ts`)**:

  - Encapsula toda a lógica de autorização.
  - Importa `TypeOrmModule.forFeature([Role])` para registrar a entidade `Role`.
  - Providencia e exporta `CaslAbilityFactory` e `PoliciesGuard`.

- **`PoliciesGuard` (`guards/policies.guard.ts`)**:

  - Um `CanActivate` guard do NestJS que protege as rotas.
  - Utiliza o `Reflector` do NestJS para ler metadados de políticas (definidos por `@CheckPolicies`) nos handlers de rota.
  - Injeta a `CaslAbilityFactory` para obter a `AppAbility` do usuário atual (obtido de `request.user`).
  - Verifica se o usuário possui as permissões necessárias executando os `PolicyHandler`s.

- **`@CheckPolicies` Decorator e `PolicyHandler` (`decorators/check-policies.decorator.ts`)**:
  - `@CheckPolicies(...handlers: PolicyHandler[])`: Decorator para anexar um ou mais `PolicyHandler`s a um método de rota ou controller.
  - `IPolicyHandler` Interface: Define a estrutura para um handler de política (`handle(ability: AppAbility): boolean`).
  - `PolicyHandlerCallback`: Permite usar uma função simples como handler.
  - `canPerform(action: Action, subject: Subjects, subjectId?: string | number, field?: string)`: Uma factory function que cria uma instância de `CanPerformActionPolicyHandler`. Este handler verifica se `ability.can(action, subject, field)` é verdadeiro.

#### Como Funciona o Fluxo de Autorização:

1.  O usuário realiza uma requisição para uma rota protegida.
2.  O `AuthGuard` (ex: `JwtAuthGuard`, configurado separadamente no `AuthModule`) é executado primeiro. Se a autenticação for bem-sucedida, ele anexa o objeto `User` (incluindo seus `roles`) à `request`.
3.  O `PoliciesGuard` é ativado.
4.  O `PoliciesGuard` obtém os `PolicyHandler`s da rota usando `Reflector` e a chave `CHECK_POLICIES_KEY`. Se não houver handlers, o acesso é permitido por padrão (configurável).
5.  Ele extrai o `user` da `request`. Se não houver usuário, lança `ForbiddenException`.
6.  Utiliza a `CaslAbilityFactory` para construir o objeto `AppAbility` para o `user`. A factory itera sobre os `roles` do usuário e suas `permissions` para definir o que o usuário `can` ou `cannot` fazer.
7.  O `PoliciesGuard` executa cada `PolicyHandler` registrado para a rota, passando o `AppAbility` do usuário.
    - Por exemplo, se uma rota usa `@CheckPolicies(canPerform(Action.Read, Article))`, o `CanPerformActionPolicyHandler` verificará `ability.can(Action.Read, Article)`.
8.  Se _todos_ os `PolicyHandler`s retornarem `true`, o acesso à rota é concedido.
9.  Se qualquer `PolicyHandler` retornar `false`, o `PoliciesGuard` lança uma `ForbiddenException`, negando o acesso.

#### Como Implementar Autorização em Novos Módulos/Rotas:

1.  **Definir Permissões para Papéis**:

    - **Criar/Gerenciar Papéis**: Certifique-se de que os papéis (ex: `'admin'`, `'editor'`, `'viewer'`) existam na tabela `roles` do banco de dados. Cada papel deve ter um array de `CaslPermission` no seu campo `permissions`.
      - Exemplo de permissões para um papel `'editor'` que pode ler e atualizar `Article` e ler `User`:
        ```json
        [
          { "action": "Read", "subject": "Article" },
          { "action": "Update", "subject": "Article" },
          { "action": "Read", "subject": "User" }
        ]
        ```
      - A propriedade `action` deve corresponder a um valor do enum `Action`.
      - A propriedade `subject` deve ser o nome de uma entidade (ex: `'User'`, `'Article'`) ou a string `'all'`.
      - Opcionalmente, `conditions` e `fields` podem ser usados para permissões mais granulares (consulte a documentação do CASL).

2.  **Atribuir Papéis aos Usuários**:

    - Quando um usuário é criado ou atualizado, atribua os `Role` entities apropriados à sua propriedade `roles`. O TypeORM cuidará da tabela de junção `user_roles`.

3.  **Registrar Novas Entidades (Subjects) na `CaslAbilityFactory`**:

    - Para criar uma nova entidade (ex: `Product`) que será usada como `subject` nas permissões:
      1.  Importe a classe da entidade em `api/src/modules/authorization/casl/casl-ability.factory.ts`.
      2.  Adicione a entidade ao tipo `Subjects`:
          ```typescript
          // import { Product } from '../../product/entities/product.entity';
          // export type Subjects = InferSubjects<typeof User | typeof Article | typeof Product | 'all'>;
          ```
      3.  Adicione a entidade ao `subjectConstructorMap`:
          ```typescript
          // private subjectConstructorMap: Record<string, any> = {
          //   User: User,
          //   Article: Article,
          //   Product: Product, // Adicionar aqui
          // };
          ```

4.  **Proteger Rotas nos Controllers**:

    - Importe `PoliciesGuard`, `CheckPolicies`, `canPerform` (ou seus handlers customizados) e o enum `Action`.
      ```typescript
      import { Controller, Get, UseGuards, Param } from '@nestjs/common';
      import { AuthGuard } from '@nestjs/passport'; // Ou seu guard de autenticação específico
      import { PoliciesGuard } from 'src/modules/authorization/guards/policies.guard';
      import {
        CheckPolicies,
        canPerform,
      } from 'src/modules/authorization/decorators/check-policies.decorator';
      import { Action } from 'src/modules/authorization/casl/casl-ability.factory';
      import { Article } from '../article/entities/article.entity'; // Exemplo de entidade
      ```
    - Aplicar os guards à classe do controller ou a métodos específicos. **Importante**: O `AuthGuard` deve vir _antes_ do `PoliciesGuard`.
      ```typescript
      @Controller('articles')
      @UseGuards(AuthGuard('jwt'), PoliciesGuard)
      export class ArticlesController {
        // ...
      }
      ```
    - Utilizar o decorator `@CheckPolicies` para especificar as permissões necessárias para cada rota:

      ```typescript
      @Get()
      @CheckPolicies(canPerform(Action.Read, Article)) // Precisa ter permissão para ler a entidade Article
      findAll() {
        // Lógica para buscar todos os artigos
      }

      @Get(':id')
      @CheckPolicies(canPerform(Action.Read, Article)) // Ainda verifica permissão para ler o tipo Article
      // Para verificar a instância específica, veja "Permissões Baseadas em Atributos/Instâncias"
      findOne(@Param('id') id: string) {
        // Lógica para buscar um artigo por ID
      }

      @Post()
      @CheckPolicies(canPerform(Action.Create, Article))
      create(@Body() createArticleDto: CreateArticleDto) {
        // Lógica para criar um artigo
      }
      ```

#### Permissões Baseadas em Atributos/Instâncias (Avançado):

Para cenários como "um usuário só pode editar seus próprios artigos" ou "um usuário só pode ver pedidos se o status for 'pendente'", você precisará de uma lógica mais refinada:

1.  **Definir Permissões com Condições no Papel**:
    No `permissions` array da entidade `Role`, você pode adicionar `conditions`. Exemplo: um usuário com papel `author` só pode atualizar `Article` se `authorId` no artigo for igual ao seu `id`.

    ```json
    {
      "action": "Update",
      "subject": "Article",
      "conditions": { "authorId": "${user.id}" } // CASL pode interpolar {user.id}
    }
    ```

    Sua `CaslAbilityFactory` já está configurada para passar `conditions` para `can()`.

2.  **Adaptar `PolicyHandler`s ou `PoliciesGuard`**:

    - O `PolicyHandler` (ou o `PoliciesGuard`) precisaria carregar a instância do objeto que está sendo acessado (ex: buscar o `Article` do banco de dados usando o `id` da rota).
    - Então, a verificação seria `ability.can(Action.Update, articleInstance)`. O CASL aplicaria as `conditions` definidas na ability contra a `articleInstance`.
    - Isso geralmente envolve injetar o serviço do respectivo módulo (ex: `ArticleService`) no seu `PolicyHandler` customizado ou diretamente no `PoliciesGuard` (embora handlers customizados sejam mais modulares).

    Exemplo de um `PolicyHandler` customizado (conceitual):

    ```typescript
    // Em um arquivo de policy handlers
    export class CanManageSpecificArticlePolicyHandler
      implements IPolicyHandler
    {
      constructor(
        private readonly action: Action,
        private readonly articleService: ArticleService,
      ) {}
      async handle(ability: AppAbility, request: any): Promise<boolean> {
        // Precisa do request para pegar o ID
        const articleId = request.params.id; // Ou de onde vier o ID
        if (!articleId) return false;
        const article = await this.articleService.findOne(articleId); // Buscar a instância
        if (!article) return false; // Ou lançar NotFoundException antes do guard
        return ability.can(this.action, article);
      }
    }
    ```

    Este handler precisaria ser instanciado e passado para `@CheckPolicies`. O `PoliciesGuard` precisaria ser modificado para suportar handlers assíncronos e passar o `request` ou parâmetros relevantes para o handler.

## Comandos Disponíveis

- `yarn start:dev` ou `npm run start:dev`: Inicia o servidor em modo de desenvolvimento com watching.
- `yarn start:debug` ou `npm run start:debug`: Inicia o servidor em modo de debug com watching.
- `yarn start:prod` ou `npm run start:prod`: Inicia o servidor em modo de produção.
- `yarn build` ou `npm run build`: Compila a aplicação TypeScript.
- `yarn lint` ou `npm run lint`: Executa o linter (ESLint).
- `yarn format` ou `npm run format`: Formata o código com Prettier.
- `yarn test` ou `npm run test`: Executa testes unitários.
- `yarn test:watch` ou `npm run test:watch`: Executa testes unitários em modo watch.
- `yarn test:cov` ou `npm run test:cov`: Executa testes unitários e gera relatório de cobertura.
- `yarn test:e2e` ou `npm run test:e2e`: Executa testes end-to-end.

### Comandos TypeORM (usando `data-source.ts`):

(Adapte `yarn typeorm` para `npm run typeorm --` se estiver usando npm)

- **Gerar uma nova migração**:
  ```bash
  yarn typeorm migration:generate -d ./src/data-source.ts ./src/migrations/NomeDaSuaMigracao
  ```
- **Executar migrações pendentes**:
  ```bash
  yarn typeorm migration:run -d ./src/data-source.ts
  ```
- **Reverter a última migração**:
  ```bash
  yarn typeorm migration:revert -d ./src/data-source.ts
  ```
- **Mostrar status das migrações**:
  ```bash
  yarn typeorm migration:show -d ./src/data-source.ts
  ```

### Comandos Docker:

- `docker-compose -f ./docker/docker-compose.yml up -d`: Inicia os contêineres Docker em background.
- `docker-compose -f ./docker/docker-compose.yml down`: Para e remove os contêineres Docker.
- `docker-compose -f ./docker/docker-compose.yml logs -f postgres redis`: Visualiza logs dos serviços.
  (Verifique seu `package.json` para scripts como `docker:up` e `docker:down` que podem simplificar isso).

## Técnicas de Segurança Implementadas

### Headers de Segurança (via Helmet e configuração Fastify)

- **X-Content-Type-Options**: Previne MIME-sniffing (`nosniff`).
- **X-Frame-Options**: Proteção contra clickjacking (`SAMEORIGIN` ou `DENY`).
- **Content-Security-Policy (CSP)**: Ajuda a prevenir XSS e outros ataques de injeção de código.
- **Strict-Transport-Security (HSTS)**: Força conexões HTTPS após a primeira visita.
- **Referrer-Policy**: Controla quais informações de referência são enviadas.
- **X-DNS-Prefetch-Control**: Controla o prefetching de DNS.
- Outros headers configurados pelo Helmet para maior segurança.

### Proteção de Dados e Aplicação

- **Validação de Entrada**: `class-validator` e `ValidationPipe` global para garantir que os dados de entrada estejam no formato esperado.
- **Transformação de Dados**: `class-transformer` para transformar payloads de entrada em instâncias de DTO e para controlar a serialização de saída.
- **Serialização de Saída**: Exclusão automática de dados sensíveis (ex: senhas) usando `@Exclude()` do `class-transformer` em entidades.
- **Compressão de Resposta**: Usando `@fastify/compress` para reduzir o tamanho das respostas.
- **CORS (Cross-Origin Resource Sharing)**: Configuração granular de quais origens podem acessar a API.
- **CSRF Protection**: Usando `@fastify/csrf-protection` para proteger contra ataques Cross-Site Request Forgery em rotas que manipulam estado (POST, PUT, DELETE).
- **Rate Limiting (Throttling)**:
  - Uso de `@nestjs/throttler` para proteção geral contra abuso de API, configurável via variáveis de ambiente (`THROTTLE_TTL`, `THROTTLE_LIMIT`).
  - **Bloqueio de IP por Falhas de Login**: Mecanismo adicional que rastreia tentativas de login falhas por IP. Após um número configurável de falhas (`FAILED_LOGIN_MAX_ATTEMPTS`) dentro de uma janela de tempo (`FAILED_LOGIN_WINDOW_SECONDS`), o IP é bloqueado por um período (`FAILED_LOGIN_BLOCK_SECONDS`). Esta lógica utiliza Redis para persistência.
    - É crucial garantir que o `trustProxy` esteja configurado corretamente no adaptador HTTP (Fastify) em `main.ts` se a aplicação estiver atrás de um proxy reverso, para que o IP correto do cliente seja utilizado.

### Controle de Acesso

- **Autenticação (JWT)**:
  - Implementada com `@nestjs/passport`, `passport-jwt` e `@nestjs/jwt`.
  - **Refresh Tokens**:
    - Tokens de acesso (`access_token`) possuem curta duração (configurável, ex: 15 minutos) para segurança aprimorada.
    - Refresh tokens (`refresh_token`) de longa duração (configurável, ex: 7 dias) são emitidos para permitir que os usuários obtenham novos tokens de acesso sem reinserir credenciais.
    - Hashes dos refresh tokens são armazenados de forma segura no Redis com TTL correspondente à sua validade.
    - Endpoint `POST /auth/refresh` para renovação de tokens.
  - **Revogação de Tokens de Acesso (Blocklist)**:
    - Access tokens contêm um `jti` (JWT ID) único.
    - Endpoint `POST /auth/logout` permite que o usuário invalide seu token de acesso atual. O `jti` do token é adicionado a uma blocklist no Redis com um TTL igual ao tempo de vida restante do token.
    - A `JwtStrategy` verifica esta blocklist a cada requisição, rejeitando tokens revogados mesmo que ainda não tenham expirado naturalmente.
  - **Validação de Usuário Robusta**: A `JwtStrategy` não apenas valida a assinatura e expiração do token, mas também verifica (via `AuthService`) se o usuário associado ao token (pelo `sub` claim) ainda existe e é considerado válido no banco de dados (ex: não excluído, `isActive` se aplicável) a cada requisição.
- **Autorização Baseada em Papéis (RBAC) com CASL**:
  - Permissões granulares definidas por papéis.
  - Verificação de habilidades (`can`/`cannot`) em ações (`read`, `create`, `manage`) e sujeitos (entidades como `User`, `Article`, ou `'all'`).
  - Implementado via `AuthorizationModule`, `PoliciesGuard`, e decorators `@CheckPolicies`.

## Melhores Práticas

### Banco de Dados

- Uso de Repositórios (padrão Data Mapper do TypeORM) para abstração da camada de dados.
- Migrações para controle de versão do esquema do banco de dados.
- Uso de `data-source.ts` para configuração da CLI do TypeORM.
- SSL opcional para conexões seguras ao banco de dados (configurável via variáveis de ambiente).

### Cache

- Implementação com Redis para cache de dados frequentemente acessados.
- TTL (Time To Live) configurável.
- Pode ser estendido para estratégias de cache mais avançadas (cache-aside, write-through, etc.).

### Código

- **Estrutura Modular**: Funcionalidades organizadas em módulos NestJS.
- **Injeção de Dependências**: Amplamente utilizada para desacoplamento e testabilidade.
- **DTOs (Data Transfer Objects)**: Para validação de entrada e definição clara de contratos de API.
- **Single Responsibility Principle (SRP)**: Aplicado em services, controllers, etc.
- **Variáveis de Ambiente**: Para configuração segura e flexível entre ambientes.
- **Logging**: Logger customizado integrado.

## Extensões e Personalizações

### Adicionar um Novo Módulo

1.  Crie a estrutura de pastas para o novo módulo em `src/modules/`.
2.  Defina as entidades TypeORM (se houver interação com o banco).
3.  Crie DTOs para validação de entrada e saída.
4.  Implemente os Services com a lógica de negócio.
5.  Crie os Controllers com as rotas HTTP.
6.  Crie o arquivo `.module.ts` para o novo módulo, importando e exportando os componentes necessários.
7.  Importe o novo módulo no `src/app.module.ts`.
8.  Se o novo módulo envolver entidades que precisam ser protegidas por autorização, siga os passos descritos na seção "Como Implementar Autorização em Novos Módulos/Rotas".

### Configurar Autenticação JWT

Este boilerplate foca na autorização, mas a autenticação é um pré-requisito. Para implementar JWT:

1.  Crie (ou use) um `AuthModule`.
2.  Instale `@nestjs/passport`, `passport`, `@nestjs/jwt`, `passport-jwt` e os tipos `@types/passport-jwt`.
3.  Configure o `JwtModule` com seus segredos (`JWT_SECRET`, `JWT_REFRESH_SECRET`) e tempos de expiração (`JWT_ACCESS_TOKEN_EXPIRATION_TIME`, `JWT_REFRESH_TOKEN_EXPIRATION_TIME`) através de variáveis de ambiente.
4.  Crie uma `JwtStrategy` que valide o token (assinatura, expiração, blocklist de JTI, validade do usuário no DB) e retorne o payload do usuário.
5.  Implemente rotas de login no `AuthController` que gerem os `access_token` e `refresh_token`.
6.  Implemente uma rota `/auth/refresh` para troca de `refresh_token` por um novo par de tokens.
7.  Implemente uma rota `/auth/logout` para adicionar o `access_token` à blocklist.
8.  Use um `JwtAuthGuard` (que você criará ou usará o padrão do passport) para proteger rotas que requerem autenticação. Lembre-se de aplicá-lo _antes_ do `PoliciesGuard` se ambos forem usados.

### Adicionar Novas Configurações Customizadas

1.  Crie um novo arquivo de configuração em `src/config/` (ex: `payment.config.ts`).
2.  Use `registerAs` do `@nestjs/config` para definir um namespace para suas configurações:
    ```typescript
    // src/config/payment.config.ts
    import { registerAs } from '@nestjs/config';
    export default registerAs('payment', () => ({
      apiKey: process.env.PAYMENT_API_KEY,
      serviceUrl: process.env.PAYMENT_SERVICE_URL,
    }));
    ```
3.  Adicione as novas variáveis de ambiente (ex: `PAYMENT_API_KEY`) ao seu arquivo `.env.development`.
4.  Carregue a nova configuração no `ConfigModule` dentro de `src/app.module.ts`:
    ```typescript
    // src/app.module.ts
    // import paymentConfig from './config/payment.config';
    ConfigModule.forRoot({
      // ...,
      load: [databaseConfig, securityConfig, cacheConfig /*, paymentConfig */],
    }),
    ```
5.  Injete `ConfigService` e acesse suas configurações: `this.configService.get('payment.apiKey')`.

## Sistema de Envio de Emails (SMTP)

O boilerplate inclui um módulo completo para envio de emails usando SMTP via Nodemailer, com suporte a templates HTML usando Handlebars.

### Recursos Principais

- Configuração centralizada do servidor SMTP via variáveis de ambiente
- Templates HTML responsivos para emails (welcome, password-reset, etc.)
- Suporte a emails transacionais e de notificação
- Interface tipada para opções de envio de email
- Métodos utilitários para casos de uso comuns

### Como Utilizar

1. **Configuração**:

   Configure as variáveis de ambiente em seu arquivo `.env.development`:

   ```env
   EMAIL_HOST=smtp.seu-servidor.com
   EMAIL_PORT=587
   EMAIL_SECURE=false
   EMAIL_USER=seu-usuario@email.com
   EMAIL_PASSWORD=sua-senha
   EMAIL_FROM="Nome da Aplicação <noreply@sua-aplicacao.com>"
   ```

2. **Injeção de Dependência**:

   Injete o `EmailService` em qualquer serviço ou controlador onde você precise enviar emails:

   ```typescript
   import { Injectable } from '@nestjs/common';
   import { EmailService } from '../email/email.service';

   @Injectable()
   export class UserService {
     constructor(private readonly emailService: EmailService) {}

     async createUser(userData) {
       // Lógica para criar o usuário
       
       // Enviar email de boas-vindas
       await this.emailService.sendWelcomeEmail(
         userData.email,
         userData.name,
         'https://exemplo.com/confirm?token=abc123'
       );
     }

     async requestPasswordReset(email: string, user) {
       // Gerar token
       const resetToken = '...'; 
       
       // Enviar email de redefinição de senha
       await this.emailService.sendPasswordResetEmail(
         email,
         user.name,
         `https://exemplo.com/reset-password?token=${resetToken}`
       );
     }
   }
   ```

3. **Personalização de Templates**:

   Os templates HTML estão localizados em `src/modules/email/templates/` e usam a sintaxe Handlebars para renderização dinâmica.
   
   - Para adicionar novos templates, crie um arquivo `.hbs` neste diretório.
   - Para estender as funcionalidades, adicione novos métodos no `EmailService`.

4. **Envios Customizados**:

   Você pode usar o método genérico `sendEmail` para casos mais específicos:

   ```typescript
   await this.emailService.sendEmail({
     to: 'destinatario@email.com',
     subject: 'Assunto do Email',
     template: 'seu-template', // nome do arquivo sem extensão
     context: {
       // Variáveis disponíveis no template
       name: 'Nome do Destinatário',
       items: ['item1', 'item2'],
       totalValue: 99.9
     },
     attachments: [
       {
         filename: 'invoice.pdf',
         path: '/caminho/para/arquivo.pdf'
       }
     ]
   });
   ```

## Considerações de Produção

### Segurança Adicional

- **HTTPS Obrigatório**: Configure seu proxy reverso (Nginx, Traefik, etc.) para impor HTTPS.
- **Políticas de Senha Fortes**: Se estiver gerenciando senhas, implemente requisitos robustos.
- **Autenticação de Dois Fatores (2FA)**: Para contas de administrador ou acesso a dados sensíveis.
- **Logs de Auditoria Detalhados**: Registre eventos importantes de segurança e acesso.
- **Revisão Regular de Dependências**: Mantenha as dependências atualizadas para corrigir vulnerabilidades conhecidas.
- **WAF (Web Application Firewall)**: Considere o uso de um WAF para proteção adicional.

### Performance

- **Ajuste Fino de Cache**: Otimize TTLs e escolha o que cachear com cuidado.
- **Otimização de Consultas SQL**: Analise consultas lentas e adicione índices ao banco de dados.
- **Paginação**: Implemente paginação para endpoints que retornam grandes listas de dados.
- **Limites de Payload**: Configure limites para o tamanho dos payloads da requisição.
- **Clusterização Node.js**: Use o módulo `cluster` do Node.js ou PM2 em modo cluster para aproveitar múltiplos cores da CPU.

### Monitoramento e Logging

- **Logging Estruturado**: Use formatos como JSON para logs, facilitando a análise por ferramentas de monitoramento.
- **Health Checks Robustos**: Implemente endpoints de health check que verifiquem a saúde dos serviços dependentes (DB, Redis).
- **Monitoramento de Performance (APM)**: Integre ferramentas de APM (Datadog, New Relic, Sentry) para rastrear erros e gargalos de performance.
- **Alertas**: Configure alertas para erros críticos, problemas de performance e atividades suspeitas.
