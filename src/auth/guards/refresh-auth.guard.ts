import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class RefreshAuthGuard extends AuthGuard('refresh') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: User): any {
    if (err || !user) {
      throw new UnauthorizedException(err?.message);
    }

    return user;
  }
}
