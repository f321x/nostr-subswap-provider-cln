## <u>Submarine Swap provider plugin for CLN</u>
<mark>This plugin is work in progress and not ready to use!</mark>

This [Core Lightning](https://github.com/ElementsProject/lightning) plugin allows to
the operator to act as provider for [(reverse) submarine swaps](https://docs.lightning.engineering/the-lightning-network/multihop-payments/understanding-submarine-swaps)
to users of
[Electrum Wallet](https://electrum.org) (and others implementing the same, open protocol).
Communication is facilitated via [Nostr](https://nostr.com) and the plugin uses the database, wallet
and (newly derived) keys of the CLN node to operate, this way the user does not have to manage any additional
backup or wallet or Nostr identity.

### <u>Incentives (Reason to run this plugin alongside CLN)</u>
The swap provider can charge a proportional fee for the liquidity provided.
There is no risk of financial loss for the swap provider because the swap happens [atomically](https://cs.stackexchange.com/a/109257)
and the mining fees necessary to revert a failed swap are settled by a separate lightning payment.
A competitive fee can be chosen according to market conditions, feerates of other providers can be seen in Electrum
Wallet.

### <u>Installation</u>
You can find a detailed guide on how to install plugins in CLN using the reckless package manager
[-> here <-](https://docs.corelightning.org/docs/plugins).

For reckless to find the plugin you first have to add this repository:
```bash
$ reckless source add https://github.com/f321x/nostr-subswap-provider-cln
```

Then you can install the plugin:
```bash
$ reckless install nostr-subswap-provider-cln
```
### <u>Configuration</u>
The plugin settings are configured through [environment variables](https://kinsta.com/knowledgebase/what-is-an-environment-variable/).

The following variables are available:
- `NOSTR_RELAYS`: Comma separated string of nostr relay URIs. Example: `wss://relay.damus.io,wss://relay.primal.net,wss://nos.lol`
- `SWAP_FEE_PPM`: Fee to charge for swaps in ppm. Example: `10000` (1%)
- `CONFIRMATION_TARGET_BLOCKS`: Desired confirmation speed of onchain transactions. Example: `6`
- `FALLBACK_FEE_SATVB`: Fallback feerate to use if no reliable fee estimation is possible. Example:`65`
- `PLUGIN_LOG_LEVEL` (optional): Amount of Log output. Examples: `DEBUG`, `INFO`, `WARNING`, `ERROR`
