import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from '../dto/create-user.dto';
import { JwtService } from '@nestjs/jwt';
import { hash, compare } from 'bcrypt';
import { SendEmailDto } from '../dto/send-email.dto';
import { LoginUserDto } from '../dto/login-user.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService
    ) { }

    async register(dto: CreateUserDto) {
        const { name, email, password } = dto;

        const existsUser = await this.userRepository.findOne({ where: { email } });
        if (existsUser) throw new BadRequestException('کاربری با این ایمیل وجود دارد');

        const newUser = this.userRepository.create({
            name,
            email,
            password
        })
        let userSaved = await this.userRepository.save(newUser)

        const { accessToken, refreshToken } = await this.generateTokens(userSaved)
        userSaved.refreshToken = await hash(refreshToken, 10);
        await this.userRepository.save(userSaved)

        return { message: "کاربر با موفقیت ساخته شد", data: { accessToken, refreshToken } };
    }

    async login(dto: LoginUserDto) {
        const { email, password } = dto;

        const user = await this.userRepository.findOneBy({ email });
        if (!user) throw new NotFoundException("یوزری با این ایمیل پیدا نشد!");

        const isPasswordValidation = await compare(password, user.password);
        if (!isPasswordValidation) throw new UnauthorizedException("پسوورد صحیح نمیباشد");

        const { accessToken, refreshToken } = await this.generateTokens(user)
        return { message: "لاگین با موفقیت انجام شد", data: { accessToken, refreshToken } };
    }

    async generateTokens(user: User) {
        const payload = {
            sub: user.id,
            email: user.email,
            role: user.role,
        };

        const accessToken = this.jwtService.sign(payload, {
            expiresIn: "10m",
        })
        const refreshToken = this.jwtService.sign(payload, {
            expiresIn: "7d",
        });

        return { accessToken, refreshToken };
    }
}
