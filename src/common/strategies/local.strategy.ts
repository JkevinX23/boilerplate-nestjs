import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Strategy as LocalStrategy, IStrategyOptions } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { AuthService } from '../../modules/auth/auth.service';

@Injectable()
export class LocalAuthStrategy extends PassportStrategy(LocalStrategy) {
  constructor(private readonly authService: AuthService) {
    const options: IStrategyOptions = {
      usernameField: 'email',
    };
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    super(options);
  }

  async validate(email: string, password: string) {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Credenciais inválidas');
    }
    return user;
  }
}
