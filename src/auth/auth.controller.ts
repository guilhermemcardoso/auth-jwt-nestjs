import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { AuthService } from './auth.service';
import { IsPublic } from './decorators/is-public.decorator';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthRequest } from './models/AuthRequest';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @IsPublic()
  @Post('register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

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

  @IsPublic()
  @Get('confirm')
  @HttpCode(HttpStatus.OK)
  confirm(@Query('token') token: string) {
    return this.authService.confirmEmail(token);
  }

  @IsPublic()
  @Get('forgot-password')
  @HttpCode(HttpStatus.OK)
  forgotPassword(@Query('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @IsPublic()
  @Post('recovery-password')
  @HttpCode(HttpStatus.OK)
  recoveryPassword(
    @Body('token') recoveryToken: string,
    @Body('password') password: string,
    @Body('confirm_password') confirmPassword: string,
  ) {
    return this.authService.recoveryPassword(
      recoveryToken,
      password,
      confirmPassword,
    );
  }
}
