var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __markAsModule = (target) => __defProp(target, "__esModule", { value: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __reExport = (target, module2, copyDefault, desc) => {
  if (module2 && typeof module2 === "object" || typeof module2 === "function") {
    for (let key of __getOwnPropNames(module2))
      if (!__hasOwnProp.call(target, key) && (copyDefault || key !== "default"))
        __defProp(target, key, { get: () => module2[key], enumerable: !(desc = __getOwnPropDesc(module2, key)) || desc.enumerable });
  }
  return target;
};
var __toESM = (module2, isNodeMode) => {
  return __reExport(__markAsModule(__defProp(module2 != null ? __create(__getProtoOf(module2)) : {}, "default", !isNodeMode && module2 && module2.__esModule ? { get: () => module2.default, enumerable: true } : { value: module2, enumerable: true })), module2);
};
var __toCommonJS = /* @__PURE__ */ ((cache) => {
  return (module2, temp) => {
    return cache && cache.get(module2) || (temp = __reExport(__markAsModule({}), module2, 1), cache && cache.set(module2, temp), temp);
  };
})(typeof WeakMap !== "undefined" ? /* @__PURE__ */ new WeakMap() : 0);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  hooks: () => hooks,
  totp2fa: () => totp2fa
});

// src/hooks/totp2fa.ts
var import_errors2 = require("@feathersjs/errors");
var import_feathers_hooks_common = require("feathers-hooks-common");

// src/utils/get-qr-code-secret.ts
var import_otplib = require("otplib");
var import_qrcode = __toESM(require("qrcode"));
async function getQrCodeSecret(app, user, options) {
  const secret = user[options.secretFieldName] ? user[options.secretFieldName] : import_otplib.authenticator.generateSecret();
  const otpauth = import_otplib.authenticator.keyuri(user.email, options.applicationName, secret);
  const qrImage = await import_qrcode.default.toDataURL(otpauth);
  return { qr: qrImage, secret };
}

// src/utils/verify-token.ts
var import_otplib2 = require("otplib");
var import_errors = require("@feathersjs/errors");
function verifyToken(userToken, secret) {
  if (!userToken) {
    throw new import_errors.BadRequest("No token.");
  }
  if (!secret) {
    throw new import_errors.BadRequest("No secret.");
  }
  return import_otplib2.authenticator.verify({ token: userToken, secret });
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
    (0, import_feathers_hooks_common.checkContext)(context, "after", ["create"], "totp2fa");
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
      throw new import_errors2.BadRequest("User not found.");
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
        throw new import_errors2.BadRequest("Token required.");
      }
      if (!verifyToken(data.token, data.secret)) {
        throw new import_errors2.BadRequest("Invalid token.");
      }
      if (!user[options.secretFieldName]) {
        const patchData = {};
        const crypto = options.cryptoUtil;
        patchData[options.secretFieldName] = crypto && crypto.encrypt ? crypto.encrypt(data.secret) : data.secret;
        try {
          await usersService._patch(user[usersServiceId], patchData);
        } catch (err) {
          throw new import_errors2.BadRequest("Could not save secret.");
        }
      } else {
        throw new import_errors2.BadRequest("Secret already saved.");
      }
      return context;
    }
    if (data.token) {
      const crypto = options.cryptoUtil;
      const secret = crypto && crypto.decrypt ? crypto.decrypt(user[options.secretFieldName]) : user[options.secretFieldName];
      if (!verifyToken(data.token, secret)) {
        throw new import_errors2.BadRequest("Invalid token.");
      }
    } else {
      throw new import_errors2.BadRequest("Token required.");
    }
    delete context.result.user[options.secretFieldName];
    return context;
  };
}

// src/index.ts
var hooks = {
  totp2fa
};
module.exports = __toCommonJS(src_exports);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  hooks,
  totp2fa
});
