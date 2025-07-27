<img src="https://raw.githubusercontent.com/bRuttaZz/vanillacorn/main/misc/logo.png" align="right" width="100px">

# Vanillacorn

**Nothing but a vanilla ASGI server.**

[![pypi](https://img.shields.io/pypi/v/vanillacorn.svg)](https://pypi.org/project/vanillacorn/)
![pyright-status](https://github.com/bruttazz/vanillacorn/actions/workflows/pyright.yml/badge.svg)
![linting-status](https://github.com/bruttazz/vanillacorn/actions/workflows/linting.yml/badge.svg)
[![Release](https://img.shields.io/github/release/bruttazz/vanillacorn.svg?style=flat-square)](https://github.com/bruttazz/vanillacorn/releases/latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/bruttazz/vanillacorn/blob/main/LICENSE.txt)


A simple implementation of the ASGI specification 2.5 (2024-06-05) using pure Python and asyncio (**Py3.9 or above**).
The system is meant to use zero external libraries and contained in a single file, because why not...?

# Installation
1. Install using pip (pypi.org)
```sh
pip install vanillacorn
```

2. Single file server
```sh
# 1. Download `vanillacorn.py`
wget https://raw.githubusercontent.com/bRuttaZz/vanillacorn/refs/heads/main/vanillacorn.py

# 2. Make it executable
chmod +x vanillacorn.py

# 3. Run the server
./vanillacorn.py --help

# [or] run it with python interpreter
python3 vanillacorn.py --help
```

# Usage

```sh
usage: vanillacorn [-h] [-v] [-p PORT] [-b HOST] [-w WORKERS] [-s] [--verbose] [-l FILE] [--ssl-keyfile FILE] [--ssl-certfile FILE] [asgi_app]

A simple ASGI server: a basic implementation of the ASGI specification using pure Python and asyncio.

positional arguments:
  asgi_app              ASGI app module

options:
  -h, --help            show this help message and exit
  -v, --version         App version
  -p, --port PORT       Bind socket to this port (default: 8075)
  -b, --host HOST       Bind socket to this host. (default: localhost)
  -w, --workers WORKERS
                        Number of worker processes
  -s, --silent          Suppress console logging
  --verbose             Show detailed logging
  -l, --log-file FILE   Write server logs into log file
  --ssl-keyfile FILE    SSL key file for TLS
  --ssl-certfile FILE   SSL certfile for TLS

```

### Sample Use case
To start a simple asgi application say `main:app`
```sh
vanillacorn -p 8000 main:app

# to run in https mode
vanillacorn -p 8000 --ssl-key key.pem --ssl-cert cert.pem main:app

```

## Caveats
- Currently ignoring ws subprotocols and ws extensions


# TODO:
- [ ] implement http/ws read and buffering limits
- [ ] test cases
