import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  Headers,
} from '@nestjs/common';
import { AuthService, LoginResponse, Tokens } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LocalAuthGuard } from 'src/common/gruards/local-auth.guard';
import { JwtAuthGuard } from 'src/common/gruards/jwt-auth.guard';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Request } from 'express';

interface AuthenticatedUser {
  id: string;
  email: string;
}

interface RequestWithAuthenticatedUser extends Request {
  user: AuthenticatedUser;
}

@Controller({
  path: 'auth',
  version: '1',
})
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
  ): Promise<LoginResponse> {
    const ipAddress = req.ip;
    if (!ipAddress) {
      throw new UnauthorizedException(
        'Não foi possível determinar o endereço IP para a requisição de login.',
      );
    }
    return this.authService.login(loginDto.email, loginDto.password, ipAddress);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<Tokens> {
    return this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Headers('authorization') authHeader: string,
  ): Promise<{ message: string }> {
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const tokenValue: string = authHeader.substring(7);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      await this.authService.logout(tokenValue);
      return { message: 'Logout bem-sucedido.' };
    } else {
      throw new UnauthorizedException(
        'Token de autorização não encontrado ou malformado.',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: RequestWithAuthenticatedUser) {
    return req.user;
  }
}
