## <u>Nostr based Submarine Swap provider plugin for CLN</u>
This [Core Lightning](https://github.com/ElementsProject/lightning) plugin allows to
the operator to act as provider for submarine swaps and reverse submarine swaps to users of
[Electrum Wallet](https://electrum.org) (and others implementing the same, open protocol).
Communication is facilitated via [Nostr](https://nostr.com) and the plugin uses the database, wallet
and (derived) keys of the CLN node to operate, this way the user does not have to manage any additional
backup or wallet.