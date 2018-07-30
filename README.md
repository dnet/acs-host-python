Experimental clipboard sync host in Python
==========================================

Synchronize clipboard between devices, focusing on security and privacy.
Python and Qt is used to ease cross-platform usage.

**The code is not ready for average users, it's a proof of concept right now.**

Usage
-----

CLI is the only interface right now, provided by the awesome _Click_ library.

	Usage: acs_host.py [OPTIONS] COMMAND [ARGS]...

	Options:
	  --help  Show this message and exit.

	Commands:
	  receiver
	  register

The receiver runs until you press `Ctrl` + `C`.

Protocol
--------

### General/common conventions

 - _Nonces_ are 24 bytes long and are generated using the NaCl CSPRNG.
 - NaCl Authenticated Encryption (`crypto_box`) requires such a _nonce_,
   the nonce and the box is sent by concatenating the two in the
   following order: `nonce || box`

### Key generation and exchange

 - An X25519 EC keypair is generated at both endpoints.
 - Upon registration, the server public key is presented in a QR code.
 - As a response to the QR code, the client sends a NaCl Sealed Box with a
   _nonce_ and its own public key inside over UDP broadcast.
 - The server uses this public key and responds with this _nonce_, encrypted
   with `crypto_box` using UDP broadcast as well.

### Clipboard sharing

 - A _nonce_ is generated.
 - The contents of the clipboard is converted to a Unicode string.
 - A validity Unix timestamp and the above Unicode string is combined as a
   two-element array and serialized using CBOR.
 - The CBOR output is encrypted using the _nonce_ and a `crypto_box` and
   sent using UDP broadcast.

### Security considerations

 - For key exchange, a network eavesdropper doesn't even know the public key
   of either participant, let alone the secret key. Even if the public key of
   the server became public knowledge, although a Sealed Box could be
   constructed with the attacker's own public key, the intended client
   couldn't open the `crypto_box` sent in the reply with its own key.

 - For clipboard sharing operations, the _nonce_ can be used to filter replay
   attacks retransmitting packets verbatim. The Unix timestamp can be used
   to limit the validity of messages, and thus _nonces_ can be purged from
   the cache after the validity has expired.

License
-------

The whole project is licensed under MIT license, see `LICENSE.txt`

Dependencies
------------

 - Python 2.7
 - qrencode (Debian/Ubuntu package: `qrencode`)
 - PySodium (and thus libsodium, Debian/Ubuntu package: `python-pysodium`)
 - PyQt5 (Debian/Ubuntu package: `python-pyqt5`)
 - ipaddress (backported from Python 3, Debian/Ubuntu package: `python-ipaddress`)
 - netifaces (Debian/Ubuntu package: `python-netifaces`)
 - cbor (Debian/Ubuntu package: `python-cbor`)
 - click (Debian/Ubuntu package: `python-click`)
 - pynotify (Debian/Ubuntu package: `python-notify`)
