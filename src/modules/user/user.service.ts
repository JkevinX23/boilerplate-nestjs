import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import bcrypt from 'bcrypt';
import { UserRepository } from './user.repository';
import { CreateUserDto } from './dtos/create-user.dto';
import { Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { plainToInstance } from 'class-transformer';
import { User } from './user.entity';
@Injectable()
export class UserService {
  constructor(
    private userRepository: UserRepository,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const existingUser = await this.userRepository.findByEmail(
      createUserDto.email,
    );
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword: string = await bcrypt.hash(
      createUserDto.password,
      10,
    );

    const user = await this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });

    await this.cacheManager.del('users');

    return user;
  }

  async findAll(): Promise<User[]> {
    try {
      const cachedUsers = await this.cacheManager.get<User[]>('users');

      if (cachedUsers && Array.isArray(cachedUsers)) {
        const users = plainToInstance(User, cachedUsers, {
          excludeExtraneousValues: true,
          enableImplicitConversion: true,
        });

        if (
          users.length === cachedUsers.length &&
          users.every((u) => u instanceof User)
        ) {
          return users;
        }
      }
    } catch {
      // Ignora silenciosamente qualquer erro
      // Isso ocorre quando há algo inválido no cache
    }

    const users = await this.userRepository.findAll();
    await this.cacheManager.set('users', users, 60000);
    return users;
  }
  async findOne(id: string): Promise<User> {
    try {
      const cachedUser = await this.cacheManager.get<User>(`user-${id}`);
      if (cachedUser) {
        const user = plainToInstance(User, cachedUser, {
          excludeExtraneousValues: true,
          enableImplicitConversion: true,
        });
        if (user instanceof User) {
          return user;
        }
      }
    } catch {
      // Isso ocorre quando há algo inválido no cache
    }

    const user = await this.userRepository.findOne(id);
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    await this.cacheManager.set(`user-${id}`, user, 60000);

    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    try {
      const cachedUser = await this.cacheManager.get<User>(`user-${email}`);
      if (cachedUser) {
        const user = plainToInstance(User, cachedUser, {
          excludeExtraneousValues: true,
          enableImplicitConversion: true,
        });
        if (user instanceof User) {
          return user;
        }
      }
    } catch {
      // Isso ocorre quando há algo inválido no cache
    }

    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(`User with email ${email} not found`);
    }
    return user;
  }
}
