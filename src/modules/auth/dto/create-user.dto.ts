import { IsEmail, IsString, Min, MinLength } from 'class-validator';

export class CreateUserDto {
    @IsString()
    name: string;

    @IsEmail({}, { message: 'ایمیل نامعتبر است' })
    email: string;

    @IsString()
    @MinLength(8, { message: 'رمز عبور باید حداقل ۸ کاراکتر باشد' })
    password: string;
}
