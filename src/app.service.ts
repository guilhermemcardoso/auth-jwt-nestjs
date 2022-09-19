import { Injectable } from '@nestjs/common';
import { User } from './user/entities/user.entity';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }

  async getCurrentUser(user: User) {
    return user;
  }
}
