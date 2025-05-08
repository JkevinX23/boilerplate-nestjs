import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { EmailOptions } from './interfaces/email-options.interface';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private readonly defaultFromEmail: string;

  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {
    this.defaultFromEmail = this.configService.get<string>('email.from') || '"Boilerplate" <noreply@boilerplate.com>';
  }

  /**
   * Envia um email com as opções fornecidas
   * @param options Opções do email a ser enviado
   * @returns Promise que resolve para o resultado do envio
   */
  async sendEmail(options: EmailOptions) {
    try {
      const { to, subject, template, context, from, cc, bcc, attachments, text, html } = options;

      const mailOptions = {
        to,
        subject,
        template,
        context: {
          ...context,
          year: new Date().getFullYear(),
        },
        from: from || this.defaultFromEmail,
        ...(cc && { cc }),
        ...(bcc && { bcc }),
        ...(attachments && { attachments }),
        ...(text && { text }),
        ...(html && { html }),
      };

      const result = await this.mailerService.sendMail(mailOptions);
      this.logger.log(`Email enviado com sucesso para: ${to}`);
      return result;
    } catch (error) {
      this.logger.error(
        `Erro ao enviar email para: ${options.to}. Erro: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Envia um email de boas-vindas para um novo usuário
   * @param to Email do destinatário
   * @param name Nome do destinatário
   * @param confirmationUrl URL para confirmação de cadastro
   * @returns Promise que resolve para o resultado do envio
   */
  async sendWelcomeEmail(to: string, name: string, confirmationUrl: string) {
    return this.sendEmail({
      to,
      subject: 'Bem-vindo ao Boilerplate',
      template: 'welcome',
      context: {
        name,
        confirmationUrl,
      },
    });
  }

  /**
   * Envia um email de redefinição de senha
   * @param to Email do destinatário
   * @param name Nome do destinatário
   * @param resetLink Link para redefinição de senha
   * @returns Promise que resolve para o resultado do envio
   */
  async sendPasswordResetEmail(to: string, name: string, resetLink: string) {
    return this.sendEmail({
      to,
      subject: 'Redefinição de senha - Boilerplate',
      template: 'password-reset',
      context: {
        name,
        resetLink,
      },
    });
  }
}
