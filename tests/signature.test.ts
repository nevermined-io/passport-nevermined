import { Account, Nevermined } from '@nevermined-io/sdk'
import { config } from './config'
import { Strategy } from '../src/strategy'
import { Request } from 'express'
import { CLIENT_ASSERTION_TYPE } from '../src/jwt.utils'

describe('Test', () => {
  let nevermined: Nevermined
  let account: Account

  beforeAll(async () => {
    nevermined = await Nevermined.getInstance(config)
    ;[account] = await nevermined.accounts.list()
  })
  test('test client assertion', async () => {
    const clientAssertion = await nevermined.utils.jwt.generateClientAssertion(account)

    const strategy = new Strategy((payload: any) => {
      expect(payload.iss).toBe(account.getId())
    }, undefined)

    const mockRequest = {
      body: {
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: clientAssertion,
      },
    } as Request

    await strategy.authenticate(mockRequest)
  })

  test('test client assertion typed', async () => {
    const clientAssertion = await nevermined.utils.jwt.generateClientAssertion(
      account,
      'Hello Nevermined!',
    )

    const strategy = new Strategy((payload: any) => {
      expect(payload.iss).toBe(account.getId())
      expect(payload.eip712Data).toBeDefined()
    }, undefined)

    const mockRequest = {
      body: {
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: clientAssertion,
      },
    } as Request

    await strategy.authenticate(mockRequest)
  })
})
