import { Request } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import * as passport from "passport-strategy";
import { ParsedQs } from "qs";
import { jwtEthVerify, JwtEthVerifyError } from "./jwt.utils";

export default class Strategy extends passport.Strategy {
  name = "nvm-login";

  async authenticate(
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
    options?: any
  ) {
    const clientAssertion = req.body;
    if (
      clientAssertion.client_assertion_type !==
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ) {
      this.fail('Invalid "client_assertion_type"', 401);
    }

    try {
      const payload = jwtEthVerify(clientAssertion.client_assertion);
      return this.success(payload);
    } catch (err: any) {
      if (err instanceof JwtEthVerifyError) {
        this.fail(err.message, 401);
      } else {
        this.error(err);
      }
    }
  }
}
