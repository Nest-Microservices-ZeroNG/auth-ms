import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import {
  MicroserviceOptions,
  RpcException,
  Transport,
} from '@nestjs/microservices';
import { Logger, ValidationPipe } from '@nestjs/common';
import { envs } from './config';
import { ValidationError } from 'class-validator';

async function bootstrap() {
  const logger = new Logger('Main');
  // const app = await NestFactory.create(AppModule);
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.NATS,
      options: {
        servers: envs.natsServers,
      },
    },
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      disableErrorMessages: true,
      exceptionFactory: (validationErrors: ValidationError[] = []) => {
        return new RpcException({
          error: 'Validation Error',
          message: validationErrors.flatMap((e) =>
            Object.values(e.constraints),
          ),
        });
      },
    }),
  );

  await app.listen();
  logger.log(`Auth Microservice running on port: ${envs.port}`);
}

bootstrap();
