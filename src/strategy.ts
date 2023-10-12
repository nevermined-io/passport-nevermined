import { Request } from 'express'
import * as passport from 'passport-strategy'
import {
  ClientAssertion,
  CLIENT_ASSERTION_TYPE,
  jwtEthVerify,
  JwtEthVerifyError,
  JWTPayload,
} from './jwt.utils'
import { ethers } from 'ethers'

export interface Options {
  web3ProviderUri: string
}

export class Strategy extends passport.Strategy {
  name = 'nvm-login'
  _verify: (user: JWTPayload, verify: (err: Error, user: JWTPayload, info: number) => void) => void
  private readonly provider?: ethers.providers.JsonRpcProvider

  constructor(options: Options, verify: (user: JWTPayload) => void) {
    super()
    this._verify = verify

    this.provider = new ethers.providers.JsonRpcProvider(options.web3ProviderUri)

    passport.Strategy.call(this)
  }

  async authenticate(req: Request, _options?: unknown) {
    const clientAssertion: ClientAssertion = req.body
    if (clientAssertion.client_assertion_type !== CLIENT_ASSERTION_TYPE) {
      return this.fail('Invalid "client_assertion_type"', 401)
    }

    try {
      const payload = await jwtEthVerify(clientAssertion.client_assertion, this.provider)
      const verified = (err: Error, user: JWTPayload, info: number) => {
        if (err) {
          return this.error(err)
        }
        if (!user) {
          return this.fail(info)
        }
        this.success(user, info)
      }

      this._verify(payload, verified)
    } catch (err: unknown) {
      if (err instanceof JwtEthVerifyError) {
        return this.fail(err.message, 401)
      } else {
        return this.error(err as Error)
      }
    }
  }
}
