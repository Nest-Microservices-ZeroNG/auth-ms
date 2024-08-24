import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { envs } from '../config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit(): any {
    this.$connect();
    this.logger.log(`MongoDD success connection`);
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Already exists a user with the email provided',
        });
      }

      const createdUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });
      const { password: __, ...rest } = createdUser;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (e) {
      throw new RpcException({
        status: e.error.status ?? HttpStatus.INTERNAL_SERVER_ERROR,
        message: e.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (!user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email or password is incorrect',
        });
      }
      const isPasswordValid = bcrypt.compareSync(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email or password is incorrect',
        });
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (e) {
      throw new RpcException({
        status: e.error.status ?? HttpStatus.INTERNAL_SERVER_ERROR,
        message: e.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwt_secret,
      });
      return {
        user,
        token: await this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid Token',
      });
    }
  }
}
