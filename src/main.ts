import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import compression from '@fastify/compress';
import fastifyCsrf from '@fastify/csrf-protection';
import fastifyCors from '@fastify/cors';
import { AppModule } from './app.module';
import { CustomLogger } from './common/logger/logger.service';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      logger: false,
    }),
  );

  app.useLogger(app.get(CustomLogger));

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT', 3000);

  await app.register(fastifyCors, {
    origin: configService.get<string>('CORS_ORIGIN', '*'),
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'PATCH'],
    credentials: true,
  });

  await app.register(fastifyCsrf);

  await app.register(compression, {
    threshold: 100 * 1024, // 100KB
    encodings: ['gzip', 'deflate'],
    zlibOptions: {
      level: 6,
    },
  });

  app.use(helmet());

  app.enableVersioning({
    type: VersioningType.HEADER,
    header: 'X-API-Version',
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  await app.listen(port, '0.0.0.0');
  console.log(`Application running on ${await app.getUrl()}`);
}
bootstrap();
