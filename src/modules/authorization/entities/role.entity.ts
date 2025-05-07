import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { User } from '../../user/user.entity';

export interface CaslPermission {
  action: string;
  subject: string;
  conditions?: any;
  fields?: string[];
}

@Entity({ name: 'roles' })
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 50 })
  name: string;

  @Column({ type: 'jsonb', nullable: false, default: [] })
  permissions: CaslPermission[];

  @ManyToMany(() => User, (user) => user.roles)
  users: User[];
}
