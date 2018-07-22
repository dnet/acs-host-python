#!/usr/bin/env python
# -*- coding: utf-8 -*-

from itertools import chain
from socket import SOL_SOCKET, SO_BROADCAST
from subprocess import Popen, PIPE
from sys import argv, exit
from time import time, sleep
from threading import Thread
import SocketServer

from PyQt5 import QtCore, QtWidgets
from PyQt5.Qt import QApplication, QClipboard
from ipaddress import ip_address
import netifaces
import pysodium
import cbor

HOST = ''
REG_PORT = 9361
CLIP_PORT = 9362
SETTINGS_ORG = 'dnet'
SETTINGS_APP = 'android-clipboard-sync'
SETTINGS_APP_KEY = 'appkey/public'
SETTINGS_PK_KEY = 'keypair/public'
SETTINGS_SK_KEY = 'keypair/secret'


def get_key():
    s = QtCore.QSettings(SETTINGS_ORG, SETTINGS_APP)
    pk = s.value(SETTINGS_PK_KEY)
    sk = s.value(SETTINGS_SK_KEY)
    ap = s.value(SETTINGS_APP_KEY)
    if not (pk and sk):
        pk, sk = pysodium.crypto_box_keypair()
        s.setValue(SETTINGS_PK_KEY, QtCore.QByteArray(pk))
        s.setValue(SETTINGS_SK_KEY, QtCore.QByteArray(sk))
        s.sync()
    return str(pk), str(sk), ap and str(ap)


def register():
    # TODO this whole thing could be a GUI
    pk, sk, _ = get_key()
    qrencode = Popen(['qrencode', '-8', '-t', 'ANSIUTF8'], stdin=PIPE)
    qrencode.communicate(pk)
    print
    print 'Please scan the above QR code with the app to continue'
    packets = []

    class MyUDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            data, socket = self.request
            unsealed = pysodium.crypto_box_seal_open(data, pk, sk)
            ap = unsealed[:pysodium.crypto_box_PUBLICKEYBYTES]
            challenge = unsealed[pysodium.crypto_box_PUBLICKEYBYTES:]
            packets.append(ap)
            nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
            response = pysodium.crypto_box(challenge, nonce, ap, sk)
            dst = (src2dst(self.client_address[0]), REG_PORT)
            socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            socket.sendto(nonce + response, dst)

    server = SocketServer.UDPServer((HOST, REG_PORT), MyUDPHandler)
    while not packets:
        server.handle_request()

    unsealed = packets[0]
    s = QtCore.QSettings(SETTINGS_ORG, SETTINGS_APP)
    s.setValue(SETTINGS_APP_KEY, QtCore.QByteArray(unsealed))
    s.sync()
    print 'The app has been associated with this machine, its public key got stored'


nonces = {} # TODO clear nonces past their validity

def receiver():
    pk, sk, ap = get_key()
    packets = []

    class MyUDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            data = self.request[0]
            nonce = data[:pysodium.crypto_box_NONCEBYTES]
            if nonce in nonces:
                return
            box = data[pysodium.crypto_box_NONCEBYTES:]
            validity, payload = cbor.loads(pysodium.crypto_box_open(box, nonce, ap, sk))
            if validity < time():
                return
            nonces[nonce] = validity
            packets.append(payload)

    server = SocketServer.UDPServer((HOST, CLIP_PORT), MyUDPHandler)
    while not packets:
        server.handle_request()

    set_clipboard_text(packets[0])


def set_clipboard_text(value):
    app = QtWidgets.QApplication(argv)
    cb = QApplication.clipboard()
    cb.setText(value, cb.Clipboard)
    if cb.supportsSelection():
        cb.setText(value, cb.Selection)
    if cb.supportsFindBuffer():
        cb.setText(value, cb.FindBuffer)
    exit(app.exec_()) # TODO merge with the rest of the functionality


def src2dst(src):
    src_int = ip_num(src)
    for interface in netifaces.interfaces():
        for address in chain.from_iterable(netifaces.ifaddresses(interface).itervalues()):
            netmask_str = address.get('netmask')
            if netmask_str is None:
                continue
            try:
                netmask = ip_num(netmask_str)
                addr = ip_num(address['addr'])
            except ValueError:
                continue
            if (netmask & addr) == (netmask & src_int):
                broadcast = address.get('broadcast')
                if broadcast:
                    return broadcast
    return src


def ip_num(ip):
    return int(ip_address(unicode(ip)))

receiver()
#register()