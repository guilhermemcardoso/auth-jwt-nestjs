import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { User } from 'src/user/entities/user.entity';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { IsPublic } from './decorators/is-public.decorator';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { RefreshAuthGuard } from './guards/refresh-auth.guard';
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
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(RefreshAuthGuard)
  refresh(@CurrentUser() user: User) {
    return this.authService.refreshToken(user);
  }
}
