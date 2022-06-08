import { HookContext } from '@feathersjs/feathers';

declare type User = {
    id: string;
    email: string;
    base32secret: string;
};
interface TotpOptions {
    usersService: string;
    secretFieldName: string;
    requiredFieldName: string;
    cryptoUtil: CryptoUtil;
    applicationName: string;
}
interface CryptoUtil {
    encrypt(text: string): string;
    decrypt(text: string): string;
}
interface QrImageSecret {
    qr: string;
    secret: string;
}
interface VerifyResult {
    boolean: any;
}

/**
 * TOTP 2FA Hook
 *
 * To be called in the after hook of the create method in the authentication service
 */
declare function totp2fa(options?: TotpOptions): (context: HookContext) => HookContext;

declare const hooks: {
    totp2fa: typeof totp2fa;
};

export { CryptoUtil, QrImageSecret, TotpOptions, User, VerifyResult, hooks, totp2fa };
