import { verifyMessage } from '@ambire/signature-validator'
import { ethers } from 'ethers'
import * as jose from 'jose'

export interface ClientAssertion {
  client_assertion_type: string
  client_assertion: string
}

export interface Eip712Data {
  message: string
  chainId: number
}

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

export type JWTPayload = jose.JWTPayload
export class JwtEthVerifyError extends Error {}

const isValidSignature = (
  protectedHeader: string,
  payload: string,
  signature: string,
  jwtPayload: JWTPayload,
  provider?: ethers.providers.JsonRpcProvider,
): Promise<boolean> => {
  const signatureInput = `${protectedHeader}.${payload}`
  const signatureDecoded = `0x${Buffer.from(signature, 'base64').toString('hex')}`

  const { eip712Data, iss } = jwtPayload

  if (eip712Data) {
    const domain = {
      name: 'Nevermined',
      version: '1',
      chainId: (eip712Data as Eip712Data).chainId,
    }
    const types = {
      Nevermined: [
        { name: 'from', type: 'address' },
        { name: 'message', type: 'string' },
        { name: 'token', type: 'string' },
      ],
    }
    const value = {
      from: iss,
      message: (eip712Data as Eip712Data).message,
      token: signatureInput,
    }

    return verifyMessage({
      signer: iss,
      signature: signatureDecoded,
      typedData: {
        types,
        domain,
        message: value,
      },
      provider,
    })
  } else {
    return verifyMessage({
      signer: iss,
      signature: signatureDecoded,
      message: signatureInput,
      provider,
    })
  }
}

export const jwtEthVerify = async (
  jwt: string,
  provider?: ethers.providers.JsonRpcProvider,
): Promise<JWTPayload> => {
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jwt.split('.')

  if (length !== 3) {
    throw new JwtEthVerifyError('Invalid Compact JWS')
  }

  // decode and validate protected header
  let parsedProtectedHeader: jose.ProtectedHeaderParameters
  try {
    parsedProtectedHeader = jose.decodeProtectedHeader(jwt)
  } catch (error) {
    throw new JwtEthVerifyError(
      `ProtectedHeader: Failed to decode header (${(error as Error).message})`,
    )
  }
  if (parsedProtectedHeader.alg !== 'ES256K') {
    throw new JwtEthVerifyError('ProtectedHeader: Invalid algorithm')
  }

  // verify the payload
  let parsedPayload: JWTPayload
  try {
    parsedPayload = jose.decodeJwt(jwt)
  } catch (error) {
    throw new JwtEthVerifyError(`Payload: Failed to decode payload (${(error as Error).message})`)
  }
  if (!parsedPayload.iss) {
    throw new JwtEthVerifyError('Payload: "iss" field is required')
  }

  const isValidAddress = ethers.utils.isAddress(parsedPayload.iss)
  if (!isValidAddress) {
    throw new JwtEthVerifyError('Payload: "iss" field must be a valid ethereum address')
  }
  const isChecksumAddress = ethers.utils.getAddress(parsedPayload.iss) === parsedPayload.iss
  if (!isChecksumAddress) {
    throw new JwtEthVerifyError('Payload: "iss" field must be a checksum address')
  }

  // validate the signature
  let isValid: boolean
  try {
    isValid = await isValidSignature(protectedHeader, payload, signature, parsedPayload, provider)
  } catch (error) {
    throw new JwtEthVerifyError(
      `Signature: Failed to validate signature (${(error as Error).message})`,
    )
  }

  if (!isValid) {
    throw new JwtEthVerifyError('Signature: Invalid signature.')
  }

  return parsedPayload
}
