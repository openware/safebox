# safebox

## Generate a new master key
```bash
JWT=$(./scripts/jwtgen.rb)
curl -i -XPOST -H "authorization: Bearer ${JWT}" localhost:8000/api/v2/private/master_key --data '{"driver":"btc"}'
```

## Generate a new deposit address
```bash
JWT=$(./scripts/jwtgen.rb)
curl -i -XPOST -H "authorization: Bearer ${JWT}" localhost:8000/api/v2/private/deposit_address --data '{"driver":"btc","account_id": 0,"uid": "U0000000000"}'
```

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
## Todo

 - Client to generate keypair into vault
 - Local testing environment with localnet
 - Unit test environment
 - Send transaction by CLI
 - Validate incoming transaction with RSA
 - Build Raw transaction
 - Publish with json-rpc client to remote bitcoin node
