import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { SendEmailDto } from "../dto/send-email.dto";
import { EmailService } from "src/common/services/email.service";
import { CacheService } from "src/common/services/cache.service";
import { OtpCodeDto } from "../dto/otp-code.dto";
import { hash, compare } from 'bcrypt';
import { JwtService } from "@nestjs/jwt";
import { AuthService } from "./auth.service";

@Injectable()
export class OtpService {
    constructor(
        private readonly emailService: EmailService,
        private readonly cacheService: CacheService,
        private readonly jwtService: JwtService,
        private readonly authService: AuthService
    ) { }

    async sendEmail(dto: SendEmailDto) {
        const { email } = dto;

        await this.authService.checkEmail(email)

        const otp = await this.emailService.sendOtp(email)

        console.log(otp);

        const hashedCode = await hash(otp, 10);

        await this.cacheService.set(`email:${email}`, hashedCode, 120)

        return { message: "کد با موفقیت ارسال شد" }
    }

    async verifyOtp(dto: OtpCodeDto) {
        const { email, code } = dto;

        const codeHashed = await this.cacheService.get(`email:${email}`)
        if (!codeHashed) throw new BadRequestException("ایمیل منقضی شده است");

        const isPasswordTrue = await compare(code, codeHashed)
        if (!isPasswordTrue) throw new UnauthorizedException("کد وارد شده صحیح نمی‌باشد");

        await this.cacheService.del(`email:${email}`);

        const user = await this.authService.createUser(email)

        const token = this.jwtService.sign(
            { user_id: user.id },
            {
                expiresIn: "10m",
            }
        );

        return { message: "کد درست میباشد", token }
    }
}