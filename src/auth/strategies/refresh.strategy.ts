import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { User } from 'src/user/entities/user.entity';
import { UserPayload } from '../models/UserPayload';

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: true,
        secretOrKey: process.env.JWT_ACCESS_SECRET,
      },
      {
        jwtFromRequest: ExtractJwt.fromBodyField('refresh_token'),
        ignoreExpiration: false,
        secretOrKey: process.env.JWT_REFRESH_SECRET,
      },
    );
  }

  async validate(payload: UserPayload): Promise<User> {
    return {
      id: payload.sub,
      email: payload.email,
      name: payload.name,
      password: undefined,
    };
  }
}
