import { Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { AuthService } from '../../modules/auth/auth.service';
import { User } from '../../modules/user/user.entity';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

export interface JwtStrategyPayload {
  sub: string;
  email: string;
  jti: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {
    const secret = configService.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET não está definido nas variáveis de ambiente');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: JwtStrategyPayload): Promise<Omit<User, 'password'>> {
    if (payload.jti) {
      const blocklistKey = `blocklist:jti:${payload.jti}`;
      const isBlocked = await this.cacheManager.get(blocklistKey);
      if (isBlocked) {
        throw new UnauthorizedException('Token revogado.');
      }
    } else {
      throw new UnauthorizedException('Token inválido (sem JTI).');
    }

    const user = await this.authService.validateUserFromPayload(payload);
    if (!user || !user.isActive) {
      throw new UnauthorizedException(
        'Token inválido ou usuário não encontrado.',
      );
    }
    return user;
  }
}
