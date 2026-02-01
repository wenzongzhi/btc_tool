# Bitcoin tool for study
This is a open source bitcoin tool.
You can use this tool to complete the following task
- Calculate the hash value of any file and any string
- Generate a 32 bytes (256 bit) Bitcoin private key
- Generate a public key using a private key, and generate P2PKH address (start with 1), P2WPKH address (start with bc1q), P2SH-P2WPKH address (start with 3)

## Operating environment
- Python version: 3.12.6, other versions should also work.
- Install dependencies for secp256k1 calculation
```bash
pip install ecdsa
```
```bash
pip install ecdsa bech32
```

## User guide
- generate private key
```bash
$ python bitcoin_tool.py gen
```

- calculate hash value of string
```bash
$ python bitcoin_tool.py hash -s "Satoshi Nakamoto"
```

```bash
$ python bitcoin_tool.py hash -s "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
```

- calculate hash value of file
```bash
$ python bitcoin_tool.py hash -f "E:\github\privatekey\bitcoin.pdf"
```

- generate public key/P2PKH/P2WPKH/P2SH-P2WPKH address 
```bash
$ python bitcoin_tool.py addr --privhex "1415926535897932384626433832795028841971693993751058209749445923"
```