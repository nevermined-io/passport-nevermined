import { NeverminedOptions, makeAccounts } from '@nevermined-io/sdk'

export const config: NeverminedOptions = {
  web3ProviderUri: 'http://contracts.nevermined.localnet',
  marketplaceUri: 'http://marketplace.nevermined.localnet',
  neverminedNodeUri: 'http://node.nevermined.localnet',
  artifactsFolder: './artifacts',
  circuitsFolder: './circuits',
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  accounts: makeAccounts(process.env.SEED_WORDS!),
}
