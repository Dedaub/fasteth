# fasteth

Originally developed by ArchibaldCapital this library was intended to provide a simplistic asynchronous interface for Web3 calls.

This is currently a WIP project, but we'll work to improve it

## Installing

```sh
poetry install
```

## Testing

```sh
npm install ganache --global
ssh -L 8090:127.0.0.1:8090 node-portal -N &
ganache --fork "http://127.0.0.1:8090/ethereum" &> ganache.log &
pytest
```
