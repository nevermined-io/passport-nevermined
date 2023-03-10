import { Request } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import * as passport from 'passport-strategy'
import { ParsedQs } from 'qs'
import {
  ClientAssertion,
  CLIENT_ASSERTION_TYPE,
  jwtEthVerify,
  JwtEthVerifyError,
} from './jwt.utils'

export class Strategy extends passport.Strategy {
  name = 'nvm-login'
  // TODO: Check the types
  _verify: any

  constructor(options: any, _verify: any) {
    super()
    this._verify = options
    passport.Strategy.call(this)
  }

  async authenticate(
    req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
    _options?: any,
  ) {
    const clientAssertion: ClientAssertion = req.body
    if (clientAssertion.client_assertion_type !== CLIENT_ASSERTION_TYPE) {
      return this.fail('Invalid "client_assertion_type"', 401)
    }

    try {
      const payload = jwtEthVerify(clientAssertion.client_assertion)
      const verified = (err: any, user: any, info: any) => {
        if (err) {
          return this.error(err)
        }
        if (!user) {
          return this.fail(info)
        }
        this.success(user, info)
      }

      this._verify(payload, verified)
    } catch (err: any) {
      if (err instanceof JwtEthVerifyError) {
        return this.fail(err.message, 401)
      } else {
        return this.error(err)
      }
    }
  }
}
