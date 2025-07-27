# Vanillacorn

A vanilla ASGI server: a basic implementation of the ASGI specification using pure Python and asyncio.
The system is meant to use zero external libraries and contain in a single file, because why not..? (trying to be cool)

# TODO:
- [x] support websocket transport
- [ ] implement http/ws read and buffering limits
- [ ] test cases
- [ ] tsl if possible to make it ground simple
- [ ] readme


## Caveats
- currently ignoring ws subprotocols and ws extensions
