import {
  BadRequestException,
  Injectable,
  NestMiddleware,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class RefreshValidationMiddleware implements NestMiddleware {
  async use(req: Request, res: Response, next: NextFunction) {
    const { refresh_token: refreshToken } = req.body;

    if (!refreshToken) {
      throw new BadRequestException();
    }

    next();
  }
}
