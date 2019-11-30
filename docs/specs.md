# Safebox Specifications

## Key management

### Creating the key

```
safebox -create NAME PASSPHRASE
```

safebox must store the private key in safebox/currency/name

### Signing process

After safebox validate the transaction to execute
it will read the private key and keep it in memory until signature is performed
then destroy it.

## API Usage

### Post transaction

```
{ payload: "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  signatures: [
    { protected: "eyJhbGciOiJSUzI1NiJ9",
      header: { kid: "peatio" },
      signature: "cC4hiUPoWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    },
    { protected: "eyJhbGciOiJFUzI1NiJ9",
      header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
      signature: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    }
  ]
}
```

### With payload

```
{
  "uid":        "U123",
  "tid":        "42",
  "net":        "bitcoin-mainnet",
  "sender":     "hotwalletname",
  "recipient":  "",
  "amount":     "0.1"
}
```
