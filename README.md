# safebox

## Example of wallet configuration in peatio

```yaml
- name:             Bitcoin Hot Wallet
  blockchain_key:   btc-testnet
  currency_id:      btc
  # Address where deposits will be collected to.
  address:          '2N4qYjye5yENLEkz4UkLFxzPaxJatF3kRwf'  # IMPORTANT: Always wrap this value in quotes!
  kind:             hot       # Wallet kind (deposit, hot, warm, cold or fee).
  max_balance:      0.0
  status:           active
  gateway:          safebox  # Gateway client name.
  settings:
    uri:            http://safebox:8080
    type:           hdwallet
    account_id:     0
    wallet_id:      "xpub..."
    driver:         btc      # (btc, eth, erc20)
```
