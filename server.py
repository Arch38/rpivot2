#!/usr/bin/env python

import socket
import select
import sys
import time
import struct
from struct import pack, unpack
import random
import errno
import relay
import threading
import optparse
from common import create_logger, b, to_hex, ls


class RelayServer:
    def __init__(self, host, port, client_sock):
        self.input_list = []
        self.channel = {}
        self.last_ping_time = time.time()
        self.id_by_socket = {}
        self.pending_socks_clients = []
        self.client_sock = client_sock
        self.input_list.append(self.client_sock)
        self.remote_side_down = False

        logger.debug('Starting ping thread')

        self.ping_thread = threading.Thread(target=self.ping_worker, name='Ping')
        self.ping_thread.start()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind((host, port))
            self.server.listen(2000)
        except socket.error as err:
            (code, msg) = err.args
            logger.error('Error binding socks proxy: {0}.\nClosing socket...'.format(msg))
            self.client_sock.close()
            raise

    def ping_worker(self):
        while True:
            time.sleep(100)
            current_time = time.time()
            if self.remote_side_down:
                logger.debug('Remote side is down, exiting...')
                return
            if current_time - self.last_ping_time > relay.relay_timeout:
                logger.error('No response from the client for {0} seconds. '
                             'Restarting relay...'.format(relay.relay_timeout))
                self.client_sock.close()
                return

            try:
                self.send_remote_cmd(relay.PING_CMD)
            except socket.error as err:
                (code, msg) = err.args
                logger.debug('{0} {1}. Closing socket...'.format(code, msg))
                self.client_sock.close()
                return
            except relay.RelayError as err:
                logger.debug('{}. Exiting...'.format(err))
                self.shutdown()
                return

    def shutdown(self):
        relay.close_sockets(self.input_list)
        self.remote_side_down = True

    def main_loop(self):
        self.input_list.append(self.server)
        while True:
            time.sleep(relay.delay)

            try:
                logger.debug("Active channels: {0}".format(ls(self.channel.keys())))
                inputready, _, _ = select.select(self.input_list, [], [])
            except socket.error as err:
                (code, msg) = err.args
                logger.debug('Socket error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
                return
            except KeyboardInterrupt:
                logger.debug('SIGINT received. Closing relay and exiting...')
                self.shutdown()
                sys.exit(1)

            for inp_sock in inputready:
                if inp_sock == self.server:
                    socks_client_socket, clientaddr = self.server.accept()
                    logger.info("New connection from a client program {}:{}".format(clientaddr[0], clientaddr[1]))
                    self.input_list.append(socks_client_socket)
                    self.pending_socks_clients.append(socks_client_socket)
                elif inp_sock == self.client_sock:
                    try:
                        logger.debug("Processing client...")
                        self.manage_remote_socket()
                    except relay.RelayError:
                        logger.debug('Main loop: got RelayError. Closing connection with remote side and exiting loop')
                        self.shutdown()
                        return
                elif inp_sock in self.pending_socks_clients:
                    self.pending_socks_clients.remove(inp_sock)
                    try:
                        # setting up a connection with a client program
                        ip, port = self.handle_new_socks_connection(inp_sock)
                    except relay.RelayError as err:
                        logger.error('Error while openning a connection with a client program: {}'.format(err))
                        logger.debug("Closing socks client socket {0}".format(inp_sock))
                        self.input_list.remove(inp_sock)
                        inp_sock.close()
                        continue
                    # self.input_list.append(inp_sock)
                    new_channel_id = self.set_channel(inp_sock)
                    logger.debug("Sending command to a client to open a channel {0} "
                                 "for a new client program".format(new_channel_id))
                    self.send_remote_cmd(relay.CHANNEL_OPEN_CMD, new_channel_id, ip, port)

                elif inp_sock in self.id_by_socket:
                    self.manage_socks_client_socket(inp_sock)
                else:
                    logger.debug("Active socket {0} does not belong to channel. "
                                 "Closing it".format(inp_sock))
                    inp_sock.close()

    @staticmethod
    def parse_socks_header(data):
        """
        https://www.openssh.com/txt/socks4.protocol
        """
        try:
            (vn, cd, dstport, dstip) = unpack('>BBHI', data[:8])
        except struct.error:
            logger.debug('Invalid socks header! Got data: {0}'.format(repr(data)))
            raise relay.RelayError
        if vn != 4:
            logger.debug('Invalid socks header! Only Socks4 supported')
            raise relay.RelayError
        str_ip = socket.inet_ntoa(pack(">L", dstip))
        logger.debug('Socks Header: socks version: {0}; '
                     'socks command: {1}; dstport: {2}; dstip: {3}'.format(vn, cd, dstport, str_ip))
        return str_ip, dstport

    def get_channel_data(self):
        try:
            tlv_header = relay.recvall(self.client_sock, 4)
            channel_id, tlv_data_len = unpack('<HH', tlv_header)
            data = relay.recvall(self.client_sock, tlv_data_len)
        except socket.error as err:
            (code, msg) = err.args
            logger.debug('Exception on receiving tlv message from remote side. '
                         'Errno: {} Msg: {}. Exiting...'.format(errno.errorcode[code], msg))
            raise relay.RelayError
        return channel_id, data

    def manage_remote_socket(self):
        channel_id, data = self.get_channel_data()
        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            logger.debug('[channel {}] Got data to relay from remote side. '
                         'Data length: {}.'.format(channel_id, len(data)))
            self.relay(data, relay_to_sock)
        else:
            logger.debug('[channel {}] Relay from the client socket {} is not possible. '
                         'Channel does not exist'.format(channel_id, self.client_sock))
            return

    def manage_socks_client_socket(self, sock):
        try:
            data = sock.recv(relay.buffer_size)
        except socket.error as err:
            (code, msg) = err.args
            logger.debug('[channel {}] Exception on reading socket {}.'
                         'Details: {}, {}'.format(self.id_by_socket[sock], sock, errno.errorcode[code], msg))
            self.close_socks_connection(sock)
            return
        data_len = len(data)
        if data_len == 0:
            self.close_socks_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<HH', channel_id, len(data))
            logger.debug('[channel {}] Got data to relay from the app. Data length: {}'.format(channel_id, len(data)))
            logger.debug('[channel {}] Preparint tlv header: {}'.format(channel_id, to_hex(tlv_header)))
            # logger.debug('[channel {}] Data contents: {}'.format(channel_id, to_hex(data)))
            self.relay(tlv_header + data, self.client_sock)

    def handle_remote_cmd(self, data):
        cmd = b(data[0])
        logger.debug('Received command from the cient side: {}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id not in self.channel:
                logger.warning('[channel {}] Channel already closed'.format(channel_id))
                return
            else:
                sock_to_close = self.channel[channel_id]
                self.input_list.remove(sock_to_close)
                self.unset_channel(channel_id)
                logger.debug('[channel {}] Closing socket {}...'.format(channel_id, sock_to_close))
                sock_to_close.close()
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id in self.channel:
                logger.debug('[channel {}] Forward connection successful'.format(channel_id))
                sock = self.channel[channel_id]
                try:
                    sock.send(relay.socks_server_reply_success)
                except socket.error as err:
                    (code, msg) = err.args
                    logger.error('[channel {}] Socket error on replying SUCCESS to socks client. '
                                 'Code {}. Msg {}'.format(channel_id, code, msg))
                    logger.debug('[channel {0}] Closing client socket and sending channel close cmd to remote side')
                    sock = self.channel[channel_id]
                    self.input_list.remove(sock)
                    self.unset_channel(channel_id)
                    try:
                        sock.close()
                    except socket.error:
                        logger.debug('[channel {}] Error on closing socket'.format(channel_id))

                    self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)
            else:
                logger.debug('[channel {}] Forward connection successful. '
                             'But channel already closed'.format(channel_id))
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('[channel {}] Forward connection failed'.format(channel_id))
            if channel_id in self.channel:
                sock = self.channel[channel_id]
                try:
                    sock.send(relay.socks_server_reply_fail)
                except socket.error as err:
                    (code, msg) = err.args
                    logger.error('[channel {}] Socket error on replying FAILURE to socks client. '
                                 'Code {}. Msg {}'.format(channel_id, code, msg))
                self.input_list.remove(sock)
                self.unset_channel(channel_id)
                try:
                    sock.close()
                except socket.error as err:
                    (code, msg) = err.args
                    logger.debug('channel {}] Error on closing socket: Code {}. Msg {}'.format(channel_id, code, msg))
            else:
                logger.warning('[channel {}] Tried to close channel that is already closed'.format(channel_id))

        elif cmd == relay.CLOSE_RELAY:
            logger.info('Got command to close relay. Closing connection with client.')
            raise relay.RelayError
        elif cmd == relay.PING_CMD:
            # logger.debug('Got ping response from remote side. Good.')
            self.last_ping_time = time.time()
        else:
            logger.debug('Unknown command received: {}'.format(cmd.encode('hex')))
            raise relay.RelayError

    def send_remote_cmd(self, cmd, *args):
        logger.debug('Sending command to a client: {0}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.CHANNEL_OPEN_CMD:
            channel_id, ip, port = args
            cmd_buffer = cmd + pack('<H', channel_id) + socket.inet_aton(ip) + pack('<H', port)
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        else:
            cmd_buffer = cmd
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        try:
            self.client_sock.send(tlv_header + cmd_buffer)
        except socket.error as err:
            (code, msg) = err.args
            logger.error('Socket error on sending command to remote side. Code {0}. Msg {1}'.format(code, msg))
            raise relay.RelayError

    def handle_new_socks_connection(self, sock):
        logger.debug('Setting up a connection with a client program')
        try:
            # Getting socks header from a client program
            data = sock.recv(9)
            logger.debug('Got header: {}'.format(data))
            if len(data) != 9 or b(data[-1]) != b'\x00':
                raise relay.RelayError('Corrupted header: {}'.format(data))
        except socket.error as err:
            (code, msg) = err.args
            raise relay.RelayError('Socket error: {} {}'.format(errno.errorcode[code], msg))

        if len(data) == 0:
            raise relay.RelayError('Socks client prematurely ended connection')

        return self.parse_socks_header(data)

    def set_channel(self, sock):
        new_channel_id = self.generate_new_channel_id()
        self.channel[new_channel_id] = sock
        self.id_by_socket[sock] = new_channel_id
        return new_channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]

    def generate_new_channel_id(self):
        channel_ids = self.channel.keys()
        while True:
            rint = random.randint(1, 65535)
            if rint not in channel_ids:
                return rint

    def close_socks_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('[channel {}] Closing socks client socket {}'.format(channel_id, sock))
        logger.debug('[channel {}] Notifying remote side...'.format(channel_id))
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)

    def relay(self, data, to_socket):
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as err:
            (code, msg) = err.args
            logger.debug('Exception on relaying data to socket {0}'.format(to_socket))
            logger.debug('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            if to_socket == self.client_sock:
                raise relay.RelayError

            logger.debug('Closing socket')
            to_socket.close()
            self.input_list.remove(to_socket)
            channel_id = self.id_by_socket[to_socket]
            self.unset_channel(channel_id)
            self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)


def run_server(host, port, proxy_host, proxy_port):
    logger.info('============ Start proxy server ============')

    while True:
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serversock.bind((host, port))
            serversock.listen(5)
        except socket.error:
            logger.error('Exception binding socket at {0}:{1}'.format(host, port))
            time.sleep(1)
            break

        try:
            (backconnect, address) = serversock.accept()
        except KeyboardInterrupt:
            logger.error('SIGINT received. Shutting down')
            sys.exit(1)

        logger.info('New connection from client {0}:{1}'.format(address[0], address[1]))
        serversock.close()

        try:
            banner_rcv = backconnect.recv(4096)
            if banner_rcv != relay.banner:
                logger.error("Wrong banner {0} from the client. Closing connection".format(repr(banner_rcv)))
                backconnect.close()
                continue
            backconnect.send(relay.banner_response)
        except socket.error as err:
            (code, msg) = err.args
            logger.error("Caught socket error trying to establish connection with RPIVOT client. "
                         "Code {0}. Msg {1}".format(code, msg))
            continue

        try:
            server = RelayServer(proxy_host, int(proxy_port), backconnect)

        except socket.error:
            logger.error('Error on running relay server. Restarting...')
            continue
        try:
            server.main_loop()
        except relay.RelayError:
            logger.error('Got RelayError in server.main_loop(). Restarting relay...')
            server.server.close()
            continue

        except KeyboardInterrupt:
            logger.error("Ctrl C - Stopping server...")
            sys.exit(1)


def main():
    global logger

    parser = optparse.OptionParser(description='Reverse socks server')
    parser.add_option('--server-ip', action="store", dest='server_ip', default='0.0.0.0')
    parser.add_option('--server-port', action="store", dest='server_port', default='9999')
    parser.add_option('--proxy-ip', action="store", dest='proxy_ip', default='127.0.0.1')
    parser.add_option('--proxy-port', action="store", dest='proxy_port', default='1080')
    parser.add_option('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_option('--logfile', action="store", dest="logfile", default=None)

    cmd_options = parser.parse_args()[0]

    logger = create_logger(__name__, True, cmd_options.verbose, cmd_options.logfile)
    run_server(cmd_options.server_ip, int(cmd_options.server_port), cmd_options.proxy_ip, int(cmd_options.proxy_port))


if __name__ == "__main__":
    main()
