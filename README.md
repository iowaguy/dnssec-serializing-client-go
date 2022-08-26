# dnssec-serializing-client-go

`client` is a command line interface as a client for retrieving DNSSEC proof chains.


## Usage

To build the executable, do:

```sh
make all
```

### Query with verification

```sh
./client query --domain research.cloudflare.com. --target dnssec-serializing.research.cloudflare.com --dnssec
```
