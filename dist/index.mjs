// src/hooks/totp2fa.ts
import { BadRequest as BadRequest2 } from "@feathersjs/errors";
import { checkContext } from "feathers-hooks-common";

// src/utils/get-qr-code-secret.ts
import { authenticator } from "otplib";
import qrcode from "qrcode";
async function getQrCodeSecret(app, user, options) {
  const secret = user[options.secretFieldName] ? user[options.secretFieldName] : authenticator.generateSecret();
  const otpauth = authenticator.keyuri(user.email, options.applicationName, secret);
  const qrImage = await qrcode.toDataURL(otpauth);
  return { qr: qrImage, secret };
}

// src/utils/verify-token.ts
import { authenticator as authenticator2 } from "otplib";
import { BadRequest } from "@feathersjs/errors";
function verifyToken(userToken, secret) {
  if (!userToken) {
    throw new BadRequest("No token.");
  }
  if (!secret) {
    throw new BadRequest("No secret.");
  }
  return authenticator2.verify({ token: userToken, secret });
}

// src/options.ts
var defaultOptions = {
  usersService: "/users",
  secretFieldName: "totp2faSecret",
  requiredFieldName: "totp2faRequired",
  cryptoSetting: "crypto",
  applicationName: "Feathers App"
};

// src/hooks/totp2fa.ts
function totp2fa(options) {
  return async (context) => {
    options = Object.assign(defaultOptions, options);
    checkContext(context, "after", ["create"], "totp2fa");
    const { app, data, result } = context;
    const usersService = app.service(options.usersService);
    const usersServiceId = usersService.id;
    if (!data || !result || data.strategy !== "local") {
      return context;
    }
    let { user } = result;
    try {
      user = await usersService._get(user[usersServiceId]);
    } catch (err) {
      throw new BadRequest2("User not found.");
    }
    if (!user) {
      return context;
    }
    if (user[options.requiredFieldName] !== void 0 && !user[options.requiredFieldName]) {
      return context;
    }
    if (!data.token && !data.secret && !user[options.secretFieldName]) {
      context.result = {
        data: await getQrCodeSecret(app, user, options)
      };
      return context;
    }
    if (data.secret) {
      if (!data.token) {
        throw new BadRequest2("Token required.");
      }
      if (!verifyToken(data.token, data.secret)) {
        throw new BadRequest2("Invalid token.");
      }
      if (!user[options.secretFieldName]) {
        const patchData = {};
        const crypto = options.cryptoUtil;
        patchData[options.secretFieldName] = crypto && crypto.encrypt ? crypto.encrypt(data.secret) : data.secret;
        try {
          await usersService._patch(user[usersServiceId], patchData);
        } catch (err) {
          throw new BadRequest2("Could not save secret.");
        }
      } else {
        throw new BadRequest2("Secret already saved.");
      }
      return context;
    }
    if (data.token) {
      const crypto = options.cryptoUtil;
      const secret = crypto && crypto.decrypt ? crypto.decrypt(user[options.secretFieldName]) : user[options.secretFieldName];
      if (!verifyToken(data.token, secret)) {
        throw new BadRequest2("Invalid token.");
      }
    } else {
      throw new BadRequest2("Token required.");
    }
    delete context.result.user[options.secretFieldName];
    return context;
  };
}

// src/index.ts
var hooks = {
  totp2fa
};
export {
  hooks,
  totp2fa
};
