import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor() {
    super();
  }

  onModuleInit(): any {
    this.$connect();
    this.logger.log(`MongoDD success connection`);
  }
}
