import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CaslAbilityFactory, AppAbility } from '../casl/casl-ability.factory';
import {
  CHECK_POLICIES_KEY,
  PolicyHandler,
} from '../decorators/check-policies.decorator';
import { User } from '../../user/user.entity';

interface RequestWithUser extends Request {
  user?: User;
}

@Injectable()
export class PoliciesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private caslAbilityFactory: CaslAbilityFactory,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const policyHandlers =
      this.reflector.get<PolicyHandler[]>(
        CHECK_POLICIES_KEY,
        context.getHandler(),
      ) || [];

    if (policyHandlers.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException(
        'Usuário não autenticado ou não encontrado na requisição.',
      );
    }

    const ability = this.caslAbilityFactory.createForUser(user);

    const allPoliciesPass = policyHandlers.every((handler) =>
      this.executePolicyHandler(handler, ability),
    );

    if (!allPoliciesPass) {
      throw new ForbiddenException(
        'Você não tem permissão para realizar esta ação.',
      );
    }

    return true;
  }

  private executePolicyHandler(
    handler: PolicyHandler,
    ability: AppAbility,
  ): boolean {
    if (typeof handler === 'function') {
      return handler(ability);
    }
    return handler.handle(ability);
  }
}
