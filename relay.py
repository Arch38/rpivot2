import time
import socket


buffer_size = 4096
delay = 0.0001
socks_server_reply_success = b'\x00\x5a\xff\xff\xff\xff\xff\xff'
socks_server_reply_fail = b'\x00\x5b\xff\xff\xff\xff\xff\xff'
relay_timeout = 60
banner = b'RPIVOT'
banner_response = b'TUNNELRDY'

COMMAND_CHANNEL = 0

CHANNEL_CLOSE_CMD = b'\xcc'
CHANNEL_OPEN_CMD = b'\xdd'
FORWARD_CONNECTION_SUCCESS = b'\xee'
FORWARD_CONNECTION_FAILURE = b'\xff'
CLOSE_RELAY = b'\xc4'
PING_CMD = b'\x70'

cmd_names = {
    b'\xcc': b'CHANNEL_CLOSE_CMD',
    b'\xdd': b'CHANNEL_OPEN_CMD',
    b'\xee': b'FORWARD_CONNECTION_SUCCESS',
    b'\xff': b'FORWARD_CONNECTION_FAILURE',
    b'\xc4': b'CLOSE_RELAY',
    b'\x70': b'PING_CMD'
}


class ClosedSocket(Exception):
    pass


class RelayError(Exception):
    pass


def recvall(sock, data_len):
    buf = b''
    while True:
        buf += sock.recv(data_len - len(buf))
        if len(buf) == data_len:
            break
        time.sleep(delay)
    assert(data_len == len(buf))
    return buf


def close_sockets(sockets):
    for s in sockets:
        try:
            s.close()
        except socket.error:
            pass
