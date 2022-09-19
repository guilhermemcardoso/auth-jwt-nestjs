import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { IsPublic } from './decorators/is-public.decorator';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthRequest } from './models/AuthRequest';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(LocalAuthGuard)
  login(@Request() req: AuthRequest) {
    return this.authService.login(req.user);
  }

  @IsPublic()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(
    @Body('refresh_token') refreshToken: string,
    @Headers('Authorization') bearerToken: string,
  ) {
    const accessToken = bearerToken.replace('Bearer ', '');
    return this.authService.refreshToken(accessToken, refreshToken);
  }
}
