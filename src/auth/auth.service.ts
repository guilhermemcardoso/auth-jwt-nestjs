import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { User } from 'src/user/entities/user.entity';
import { UserPayload } from './models/UserPayload';
import { JwtService } from '@nestjs/jwt';
import { UserToken } from './models/UserToken';
import { UnauthorizedError } from './errors/unauthorized.error';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return {
          ...user,
          password: undefined,
        };
      }
    }

    throw new UnauthorizedError('Email or password provided is incorrect');
  }

  async login(user: User): Promise<UserToken> {
    const accessPayload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const accessToken = this.jwtService.sign(accessPayload, {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME,
    });

    const refreshPayload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const refreshToken = this.jwtService.sign(refreshPayload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME,
    });

    return { access_token: accessToken, refresh_token: refreshToken };
  }

  refreshToken(user: User) {
    const accessPayload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const accessToken = this.jwtService.sign(accessPayload, {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME,
    });

    const refreshPayload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const newRefreshToken = this.jwtService.sign(refreshPayload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME,
    });

    return { access_token: accessToken, refresh_token: newRefreshToken };
  }
}
