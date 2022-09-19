import {
  Injectable,
  Inject,
  CACHE_MANAGER,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { User } from 'src/user/entities/user.entity';
import { UserPayload } from './models/UserPayload';
import { JwtService } from '@nestjs/jwt';
import { UserToken } from './models/UserToken';
import { UnauthorizedError } from './errors/unauthorized.error';
import { Cache } from 'cache-manager';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
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

    await this.cacheManager.set(accessToken, refreshToken, {
      ttl: 60 * 60 * 24 * 30,
    }); // 30 days

    return { access_token: accessToken, refresh_token: refreshToken };
  }

  async refreshToken(accessToken: string, refreshToken: string) {
    const decodedAccessToken: UserPayload = this.jwtService.decode(
      accessToken,
    ) as UserPayload;

    const user = await this.userService.findByEmail(decodedAccessToken.email);

    const savedRefreshToken = await this.cacheManager.get(accessToken);

    if (savedRefreshToken !== refreshToken || !user) {
      throw new UnauthorizedException('Invalid token');
    }

    const accessPayload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const newAccessToken = this.jwtService.sign(accessPayload, {
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

    await this.cacheManager.del(accessToken);
    await this.cacheManager.set(newAccessToken, newRefreshToken, {
      ttl: 60 * 60 * 24 * 30,
    });

    return { access_token: newAccessToken, refresh_token: newRefreshToken };
  }
}
