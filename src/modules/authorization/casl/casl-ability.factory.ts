import { Injectable } from '@nestjs/common';
import {
  PureAbility,
  AbilityBuilder,
  AbilityClass,
  ExtractSubjectType,
  InferSubjects,
  MongoQuery,
} from '@casl/ability';
import { User } from '../../user/user.entity';

export enum Action {
  Manage = 'manage',
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',
}

export type Subjects = InferSubjects<typeof User | 'all'>;

export type AppAbility = PureAbility<[Action, Subjects]>;

type PermissionCondition = MongoQuery;
type SubjectType = typeof User | 'all';

@Injectable()
export class CaslAbilityFactory {
  private subjectConstructorMap: Record<string, typeof User> = {
    User: User,
  };

  createForUser(user: User): AppAbility {
    const { can, build } = new AbilityBuilder<PureAbility<[Action, Subjects]>>(
      PureAbility as AbilityClass<AppAbility>,
    );

    if (user.roles && user.roles.length > 0) {
      user.roles.forEach((role) => {
        if (role.permissions) {
          role.permissions.forEach((permission) => {
            const actionEnum = Action[permission.action as keyof typeof Action];
            if (!actionEnum) {
              console.warn(
                `Ação inválida encontrada nas permissões: ${permission.action}`,
              );
              return;
            }

            let subjectToEvaluate: SubjectType = 'all';
            if (permission.subject !== 'all') {
              const SubjectClass =
                this.subjectConstructorMap[permission.subject];
              if (!SubjectClass) {
                console.warn(
                  `Subject desconhecido encontrado nas permissões: ${permission.subject}`,
                );
                return;
              }
              subjectToEvaluate = SubjectClass;
            } else if (permission.subject === 'all') {
              subjectToEvaluate = 'all';
            }

            if (permission.conditions && permission.fields) {
              can(
                actionEnum,
                subjectToEvaluate,
                permission.fields,
                permission.conditions as PermissionCondition,
              );
            } else if (permission.fields) {
              can(actionEnum, subjectToEvaluate, permission.fields);
            } else if (permission.conditions) {
              can(
                actionEnum,
                subjectToEvaluate,
                permission.conditions as PermissionCondition,
              );
            } else {
              can(actionEnum, subjectToEvaluate);
            }
          });
        }
      });
    }

    return build({
      detectSubjectType: (item) =>
        item.constructor as ExtractSubjectType<Subjects>,
    });
  }
}
