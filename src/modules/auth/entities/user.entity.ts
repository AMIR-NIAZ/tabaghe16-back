import { BaseEntity } from 'src/common/entities/base.entity';
import { roleEnum } from 'src/common/enums/role.enum';
import { Column, Entity } from 'typeorm';

@Entity()
export class User extends BaseEntity {
    @Column()
    name: string;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @Column({ default: roleEnum.USER })
    role: string;

    @Column({ nullable: true })
    refreshToken?: string;
}
