import errno
import sys
import logging
import time

import relay
from relay import relay_timeout
import socket
import struct


def create_logger(logger_name, threads=False, verbose=False, log_file=''):
    log = logging.getLogger(logger_name)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%H:%M:%S')
    if threads:
        formatter = logging.Formatter('%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s', '%H:%M:%S')

    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    if log_file:
        ch = logging.FileHandler(log_file)
        ch.setFormatter(formatter)
        log.addHandler(ch)

    return log


def b(byte):
    """

    @param byte:
    @return: byte in '\x00' format
    """
    if sys.version_info[0] == 2:
        return byte
    return byte.to_bytes(1, byteorder='big')


def to_hex(s):
    if sys.version_info[0] == 2:
        return s.encode('hex')
    if isinstance(s, str):
        s = s.encode()
    return s.hex()


def ls(l):
    """
    List to string
    @param l: iterable
    @return: string
    """
    if not l:
        return '[]'
    return ', '.join([str(x) for x in l])


log = create_logger(__name__)


class RelayMainError(Exception):
    pass


class Relay(object):
    def __init__(self, command_socket):
        self.input_connections = list()
        self.channels = {}
        self.last_ping = time.time()
        self.remote_side_is_down = False
        self.command_socket = command_socket
        self.id_by_socket = {}

    def ping_worker(self):
        pass

    @staticmethod
    def __close_sockets(sockets):
        for s in sockets:
            try:
                s.close()
            except socket.error as err:
                log.warning(err)
                pass

    @staticmethod
    def __recvall(sock, data_len):
        """
        Receive excactly lata_len bytes from the socket.
        @return: bytestring
        """
        buf = b''
        while True:
            buf += sock.recv(data_len - len(buf))
            if len(buf) == data_len:
                break
            time.sleep(0.0001)
        assert (data_len == len(buf))
        return buf

    def shutdown(self):
        self.remote_side_is_down = True
        self.__close_sockets(self.input_connections)

    @staticmethod
    def parse_socks_header(data):
        """
        source: https://www.openssh.com/txt/socks4.protocol
        @raise: RelayMainError
        """
        try:
            (vn, cd, dstport, dstip) = struct.unpack('>BBHI', data[:8])
        except struct.error:
            raise RelayMainError('Invalid socks header! Got data: {0}'.format(repr(data)))

        if vn != 4:
            raise RelayMainError('Invalid socks header! Only Socks4 supported')

        str_ip = socket.inet_ntoa(struct.pack(">L", dstip))
        log.debug('Got header: socks version: {0}; socks command: {1}; dst: {2}:{3}'.format(vn, cd, str_ip, dstport))
        return str_ip, dstport

    def get_channel_data(self):
        """
        Getting data from the command socket (from client or from server).
        @return: tuple[int,bytes]
        @raise: RelayMainError
        """
        try:
            tlv_header = self.__recvall(self.command_socket, 4)
            channel_id, tlv_data_len = struct.unpack('<HH', tlv_header)
            data = self.__recvall(self.command_socket, tlv_data_len)
        except socket.error as err:
            (code, msg) = err.args
            raise RelayMainError('Exception on receiving tlv message from remote side.'
                                 'Errno: {} Msg: {}. Exiting...'.format(errno.errorcode[code], msg))
        return channel_id, data

    def set_channel(self, sock, channel_id):
        self.channels[channel_id] = sock
        self.id_by_socket[sock] = channel_id

    def unset_channel(self, channel_id):
        sock = self.channels[channel_id]
        del self.id_by_socket[sock]
        del self.channels[channel_id]

    def relay(self, data, to_socket):
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as err:
            (code, msg) = err.args
            log.debug('Exception on relaying data to socket {}. '
                      'Errno: {} Msg: {}'.format(to_socket, errno.errorcode[code], msg))
            if to_socket == self.command_socket:
                raise RelayMainError

            channel_id = self.id_by_socket[to_socket]
            log.debug('[channel {}] Closing socket...'.format(channel_id))
            to_socket.close()
            self.input_connections.remove(to_socket)
            self.unset_channel(channel_id)
            self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)

    def manage_socket(self):
        channel_id, data = self.get_channel_data()

        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)

        elif channel_id in self.channels:
            relay_to_sock = self.channels[channel_id]

            log.debug('[channel {}] Got data to relay from remote side. '
                      'Data length: {}.'.format(channel_id, len(data)))

            self.relay(data, relay_to_sock)

        else:
            log.debug('Relay from socket {0} with channel {1} not possible. '
                      'Channel does not exist'.format(self.command_socket, channel_id))

    def close_channel(self, channel_id):
        raise NotImplementedError

    def open_channel(self, data):
        """
        For client class only.
        """
        raise NotImplementedError

    def forward_connection_success(self, channel_id):
        """
        For server class only.
        """
        raise NotImplementedError

    def forward_connection_failue(self, channel_id):
        """
        For server class only.
        """
        raise NotImplementedError

    def handle_ping_command(self):
        pass

    def handle_remote_cmd(self, data):
        """
        @raise: RelayMainError, when unknown command received
        """
        cmd = b(data[0])
        log.debug('Received command from remote side: {0}'.format(relay.cmd_names[cmd]))

        channel_id = struct.unpack('<H', data[1:3])[0]

        if cmd == relay.CHANNEL_CLOSE_CMD:
            return self.close_channel(channel_id)

        elif cmd == relay.CHANNEL_OPEN_CMD:
            return self.open_channel(data)

        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            return self.forward_connection_success(channel_id)

        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            return self.forward_connection_failue(channel_id)

        elif cmd == relay.CLOSE_RELAY:
            log.info('Got command to close relay. Closing socket and exiting.')
            self.shutdown()

        elif cmd == relay.PING_CMD:
            self.handle_ping_command()

        else:
            raise RelayMainError('Unknown command received: {}'.format(cmd.encode('hex')))

    def send_remote_cmd(self, cmd, *args):
        """
        @raise: RelayMainError
        """
        log.debug('Sending command to a remote side: {0}'.format(relay.cmd_names[cmd]))

        if cmd in (relay.CHANNEL_CLOSE_CMD, relay.FORWARD_CONNECTION_SUCCESS, relay.FORWARD_CONNECTION_FAILURE):
            cmd_buffer = cmd + struct.pack('<H', args[0])

        elif cmd == relay.CHANNEL_OPEN_CMD:
            # for server only
            channel_id, ip, port = args
            cmd_buffer = cmd + struct.pack('<H', channel_id) + socket.inet_aton(ip) + struct.pack('<H', port)

        else:
            cmd_buffer = cmd

        tlv_header = struct.pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))

        try:
            self.command_socket.send(tlv_header + cmd_buffer)
        except socket.error as err:
            (code, msg) = err.args
            raise RelayMainError('Socket error on sending command to remote side. Code {0}. Msg {1}'.format(code, msg))
