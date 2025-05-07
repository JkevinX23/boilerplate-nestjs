import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CaslAbilityFactory } from './casl/casl-ability.factory';
import { Role } from './entities/role.entity';
import { PoliciesGuard } from './guards/policies.guard';

@Module({
  imports: [TypeOrmModule.forFeature([Role])],
  providers: [CaslAbilityFactory, PoliciesGuard],
  exports: [CaslAbilityFactory, PoliciesGuard, TypeOrmModule],
})
export class AuthorizationModule {}
