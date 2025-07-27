<img src="./misc/logo.png" align=right>

# Vanillacorn
---

A vanilla ASGI server: a basic implementation of the ASGI specification using pure Python and asyncio.
The system is meant to use zero external libraries and contain in a single file, because why not..? (trying to be cool)

# TODO:
- [x] support websocket transport
- [ ] implement http/ws read and buffering limits
- [ ] test cases
- [x] tsl if possible to make it ground simple
- [ ] readme

- after adding tls there is an issue: we actually wait till the client closes : a vulnerability (the closing handshake should be get better)
  - send close -> get close > close writer
  - get close -> send close > close writer
TODO: make sure the handhake is good to go one

## Caveats
- currently ignoring ws subprotocols and ws extensions
