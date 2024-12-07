## <u>Submarine Swap provider plugin for CLN</u>
<mark>This plugin is functional but experimental. Usage on mainnet is very reckless!</mark>

<mark>Please report any issues on GitHub and use only on testnet/signet.</mark>

This [Core Lightning](https://github.com/ElementsProject/lightning) plugin allows to
the operator to act as provider for [(reverse) submarine swaps](https://docs.lightning.engineering/the-lightning-network/multihop-payments/understanding-submarine-swaps)
to users of the
[Electrum Wallet](https://electrum.org) (and others implementing the same, open protocol).
Communication is facilitated via [Nostr](https://nostr.com), and the plugin uses the CLN node's database, wallet
and (newly derived) keys to operate, so the user does not have to manage any additional
backup, wallet or Nostr identity.

### <u>Incentives (Reason to run this plugin alongside CLN)</u>
The swap provider can charge a proportional fee for the liquidity provided.
There is no risk of financial loss for the swap provider, as the swap is atomic and
the mining fees required to unwind an unclaimed swap are settled by a separate lightning payment.
A competitive fee can be chosen according to market conditions,
fees of other providers can be seen in the Electrum Wallet.


### <u>Installation</u>
#### Bitcoin Core backend
The Plugin relies on a Bitcoin Core backend Core Lightning is setup to use. **Bitcoin Core has to enable** ```txindex=1```
for the plugin to work. The Plugin automatically uses the RPC credentials CLN is using and doesn't require any additional setup.

#### Plugin installation

You can find a detailed guide on how to install plugins in CLN using the reckless package manager
[-> here <-](https://docs.corelightning.org/docs/plugins).

For reckless to find the plugin you first have to add this repository:
```bash
reckless source add https://github.com/f321x/nostr-subswap-provider-cln
```

Then you can install the plugin:
```bash
reckless install swap-provider
```

### <u>Configuration</u>
The plugin settings are configured using [environment variables](https://kinsta.com/knowledgebase/what-is-an-environment-variable/).

The following variables are available:
- `NOSTR_RELAYS`: A comma-separated string of nostr relay URIs. Example: `wss://relay.damus.io,wss://relay.primal.net,wss://nos.lol`
- `SWAP_FEE_PPM`: Fee to charge for swaps in ppm. Example: `10000` (1%)
- `CONFIRMATION_TARGET_BLOCKS`: Desired confirmation speed of onchain transactions. Example: `6`
- `FALLBACK_FEE_SATVB`: Fallback feerate to use if no reliable fee estimation is possible. Example:`65`
- `PLUGIN_LOG_LEVEL` (optional): Level of Log output. Examples: `DEBUG`, `INFO`, `WARNING`, `ERROR`

### <u>Libraries</u>
This plugin uses a lot of Electrum Wallet code that has been stripped/modified for this use case.
It also uses the `pyln-client` library to communicate with CLN over the RPC interface.