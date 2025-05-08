import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Inject,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from 'src/modules/user/user.service';
import { User } from '../user/user.entity';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { v4 as uuidv4 } from 'uuid';

export interface Tokens {
  access_token: string;
  refresh_token: string;
}

export interface LoginResponse extends Tokens {
  user: Omit<User, 'password'>;
}

interface JwtPayload {
  sub: string;
  email: string;
  jti: string;
}

interface RefreshJwtPayload {
  sub: string;
}

export interface JwtAuthPayload {
  sub: string;
  email: string;
  jti: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  private async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  private async updateRefreshTokenStore(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const hashedRefreshToken = await this.hashData(refreshToken);
    const refreshTokenExpiresInString = this.configService.get<string>(
      'JWT_REFRESH_TOKEN_EXPIRES_IN',
      '7d',
    );
    const expiresInMs = this.parseExpiry(refreshTokenExpiresInString);
    const expiresInSeconds = expiresInMs / 1000;

    const redisKey = `user:${userId}:refreshTokenHash`;

    await this.cacheManager.set(redisKey, hashedRefreshToken, expiresInSeconds);
  }

  private parseExpiry(expiryString: string): number {
    const unit = expiryString.slice(-1);
    const value = parseInt(expiryString.slice(0, -1), 10);
    if (isNaN(value)) return 0;

    switch (unit) {
      case 's':
        return value * 1000;
      case 'm':
        return value * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      default:
        return 0;
    }
  }

  private async generateTokens(user: Omit<User, 'password'>): Promise<Tokens> {
    const jti = uuidv4();
    const accessTokenPayload: JwtPayload = {
      email: user.email,
      sub: user.id,
      jti,
    };
    const refreshTokenPayload: RefreshJwtPayload = { sub: user.id };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<string>(
        'JWT_ACCESS_TOKEN_EXPIRES_IN',
        '15m',
      ),
    });

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>(
        'JWT_REFRESH_TOKEN_EXPIRES_IN',
        '7d',
      ),
    });

    await this.updateRefreshTokenStore(user.id, refreshToken);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<Omit<User, 'password'> | null> {
    const user = await this.usersService.findByEmail(email);

    if (user && (await bcrypt.compare(password, user.password))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(
    email: string,
    password: string,
    ipAddress: string,
  ): Promise<LoginResponse> {
    const maxAttempts = this.configService.get<number>(
      'security.failedLoginAttempts.maxAttempts',
      5,
    );
    const attemptWindowSeconds = this.configService.get<number>(
      'security.failedLoginAttempts.attemptWindowSeconds',
      300,
    );
    const blockDurationSeconds = this.configService.get<number>(
      'security.failedLoginAttempts.blockDurationSeconds',
      900,
    );

    const blockedIpKey = `ipBlocked:login:${ipAddress}`;
    const loginAttemptsKey = `loginAttempts:ip:${ipAddress}`;

    // 1. Verificar se o IP está bloqueado
    const isBlocked = await this.cacheManager.get(blockedIpKey);
    if (isBlocked) {
      this.logger.warn(`Login attempt from blocked IP: ${ipAddress}`);
      throw new ForbiddenException(
        'Muitas tentativas de login. Seu IP está temporariamente bloqueado.',
      );
    }

    // 2. Verificar (e obter) contagem de tentativas falhas (não estritamente necessário antes de validateUser,
    // mas pode ser usado para uma lógica de "quase bloqueado")
    // A lógica principal de bloqueio será após a falha.

    const user = await this.validateUser(email, password);

    if (!user) {
      const attempts =
        parseInt(
          (await this.cacheManager.get<string>(loginAttemptsKey)) || '0',
          10,
        ) + 1;

      this.logger.warn(
        `Failed login attempt ${attempts}/${maxAttempts} for email ${email} from IP ${ipAddress}`,
      );

      if (attempts >= maxAttempts) {
        await this.cacheManager.set(
          blockedIpKey,
          'blocked',
          blockDurationSeconds,
        );
        await this.cacheManager.del(loginAttemptsKey); // Limpar contador de tentativas após bloquear
        this.logger.error(
          `IP ${ipAddress} blocked for ${blockDurationSeconds}s due to ${attempts} failed login attempts.`,
        );
        throw new ForbiddenException(
          'Muitas tentativas de login falhas. Seu IP foi bloqueado temporariamente.',
        );
      } else {
        await this.cacheManager.set(
          loginAttemptsKey,
          attempts.toString(),
          attemptWindowSeconds,
        );
      }
      throw new UnauthorizedException('Credenciais inválidas');
    }

    await this.cacheManager.del(loginAttemptsKey);
    this.logger.log(
      `Successful login for email ${email} from IP ${ipAddress}. Attempt counter reset.`,
    );

    const tokens = await this.generateTokens(user);

    return {
      ...tokens,
      user,
    };
  }

  async refreshToken(refreshToken: string): Promise<Tokens> {
    let payload: RefreshJwtPayload;
    try {
      payload = this.jwtService.verify<RefreshJwtPayload>(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new ForbiddenException(
        'Acesso negado. Token de atualização inválido, expirado ou malformado.',
      );
    }

    if (!payload || !payload.sub) {
      throw new ForbiddenException(
        'Acesso negado. Payload do token de atualização inválido.',
      );
    }

    const userId = payload.sub;

    const redisKey = `user:${userId}:refreshTokenHash`;
    const storedHashedRefreshToken =
      await this.cacheManager.get<string>(redisKey);

    if (!storedHashedRefreshToken) {
      throw new ForbiddenException(
        'Acesso negado. Token de atualização não encontrado, possivelmente expirado ou inválido.',
      );
    }

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      storedHashedRefreshToken,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException(
        'Acesso negado. Token de atualização inválido.',
      );
    }

    try {
      this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new ForbiddenException(
        'Acesso negado. Token de atualização corrompido ou malformado.',
      );
    }

    const user = await this.usersService.findOne(userId);
    if (!user) {
      throw new ForbiddenException('Acesso negado. Usuário não encontrado.');
    }

    const newTokens = await this.generateTokens(user);

    return newTokens;
  }

  async logout(accessToken: string): Promise<void> {
    try {
      const payload = this.jwtService.verify<JwtAuthPayload>(accessToken, {
        secret: this.configService.get<string>('JWT_SECRET'),
        ignoreExpiration: true,
      });

      if (!payload.jti || !payload.exp) {
        this.logger.warn('Tentativa de logout com token sem jti ou exp.');
        return;
      }

      const jti = payload.jti;
      const expiresAt = payload.exp * 1000;
      const now = Date.now();
      const ttlSeconds = Math.max(0, Math.floor((expiresAt - now) / 1000));

      if (ttlSeconds > 0) {
        const blocklistKey = `blocklist:jti:${jti}`;
        await this.cacheManager.set(blocklistKey, 'revoked', ttlSeconds);
        this.logger.log(
          `Token JTI ${jti} adicionado à blocklist com TTL ${ttlSeconds}s`,
        );
      } else {
        this.logger.log(
          `Token JTI ${jti} já expirado, não adicionado à blocklist.`,
        );
      }
    } catch (error) {
      this.logger.warn(
        'Falha ao verificar token durante o logout:',
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  async validateAccessToken(
    token: string,
  ): Promise<Omit<User, 'password'> | null> {
    try {
      const payload = this.jwtService.verify<JwtAuthPayload>(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      const user = await this.usersService.findOne(payload.sub);

      if (!user) {
        return null;
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result;
    } catch {
      return null;
    }
  }

  async validateAndGetUserFromAccessToken(
    token: string,
  ): Promise<Omit<User, 'password'>> {
    const user = await this.validateAccessToken(token);
    if (!user) {
      throw new UnauthorizedException(
        'Token inválido, expirado ou usuário não encontrado.',
      );
    }
    return user;
  }

  async validateUserFromPayload(
    payload: JwtAuthPayload,
  ): Promise<Omit<User, 'password'> | null> {
    if (!payload || !payload.sub) {
      return null;
    }
    const user = await this.usersService.findOne(payload.sub);
    if (!user) {
      return null;
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...result } = user;
    return result;
  }
}
