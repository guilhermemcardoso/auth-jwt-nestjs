import { Injectable, Inject, CACHE_MANAGER } from '@nestjs/common';
import { User } from './user/entities/user.entity';
import { Cache } from 'cache-manager';

@Injectable()
export class AppService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  getHello(): string {
    return 'Hello World!';
  }

  async getCurrentUser(user: User) {
    return user;
  }
}
