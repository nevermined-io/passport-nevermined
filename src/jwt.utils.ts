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

const recoverPublicKey = (
  protectedHeader: string,
  payload: string,
  signature: string,
  jwtPayload: JWTPayload,
) => {
  const signatureInput = `${protectedHeader}.${payload}`
  const signatureDecoded = `0x${Buffer.from(signature, 'base64').toString('hex')}`

  const { eip712Data, iss } = jwtPayload

  let address: string
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

    address = ethers.utils.verifyTypedData(domain, types, value, signatureDecoded)
  } else {
    address = ethers.utils.verifyMessage(signatureInput, signatureDecoded)
  }

  return ethers.utils.getAddress(address)
}

export const jwtEthVerify = (jwt: string): JWTPayload => {
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

  // recover public key from signature
  // This is the de-facto signature validation
  let publicKey: string
  try {
    publicKey = recoverPublicKey(protectedHeader, payload, signature, parsedPayload)
  } catch (error) {
    throw new JwtEthVerifyError(
      `Signature: Failed to validate signature (${(error as Error).message})`,
    )
  }

  const isValidAddress = ethers.utils.isAddress(parsedPayload.iss)
  if (!isValidAddress) {
    throw new JwtEthVerifyError('Payload: "iss" field must be a valid ethereum address')
  }
  const isChecksumAddress = ethers.utils.getAddress(parsedPayload.iss) === parsedPayload.iss
  if (!isChecksumAddress) {
    throw new JwtEthVerifyError('Payload: "iss" field must be a checksum address')
  }

  if (parsedPayload.iss !== publicKey) {
    throw new JwtEthVerifyError('Payload: "iss" is not the signer of the payload')
  }

  return parsedPayload
}
