import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { User } from '../user/entities/user.entity';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendUserConfirmation(user: User, token: string) {
    const url = `${process.env.MAIL_LINK_URL}/auth/confirm?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Welcome to Nice App! Confirm your Email',
      template: './confirmation',
      context: {
        name: user.name,
        url,
      },
    });
  }

  async sendRecoveryPassword(user: User, token: string) {
    const url = `${process.env.MAIL_LINK_URL}/auth/recovery?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject:
        'Welcome to Nice App! Click on the link to access the password recovery',
      template: './recovery',
      context: {
        name: user.name,
        url,
      },
    });
  }
}
