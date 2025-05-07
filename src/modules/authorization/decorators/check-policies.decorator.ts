import { SetMetadata } from '@nestjs/common';
import { AppAbility, Action, Subjects } from '../casl/casl-ability.factory';

export const CHECK_POLICIES_KEY = 'check_policy';

export interface IPolicyHandler {
  handle(ability: AppAbility): boolean;
}

type PolicyHandlerCallback = (ability: AppAbility) => boolean;
export type PolicyHandler = IPolicyHandler | PolicyHandlerCallback;

export const CheckPolicies = (...handlers: PolicyHandler[]) =>
  SetMetadata(CHECK_POLICIES_KEY, handlers);

export class CanPerformActionPolicyHandler implements IPolicyHandler {
  constructor(
    private readonly action: Action,
    private readonly subject: Subjects,
    private readonly subjectId?: string | number,
    private readonly field?: string,
  ) {}

  handle(ability: AppAbility): boolean {
    if (this.field && this.subjectId) {
      return ability.can(this.action, this.subject, this.field);
    } else if (this.subjectId) {
      return ability.can(this.action, this.subject);
    }
    return ability.can(this.action, this.subject);
  }
}

export const canPerform = (
  action: Action,
  subject: Subjects,
  subjectId?: string | number,
  field?: string,
) => new CanPerformActionPolicyHandler(action, subject, subjectId, field);
