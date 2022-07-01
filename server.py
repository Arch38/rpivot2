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
from common import create_logger, b, to_hex, ls, RelayMainError, Relay


class RelayServer(Relay):

    def __init__(self, host, port, command_socket):
        super(RelayServer, self).__init__(command_socket)
        self.pending_socks_clients = []

        self.ping_thread = threading.Thread(target=self.ping_worker, name='Ping')
        self.ping_thread.start()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind((host, port))
            self.server.listen(2000)
        except socket.error as err:
            (code, msg) = err.args
            log.error('Error binding socks proxy: {0}.\nClosing socket...'.format(msg))
            self.command_socket.close()
            raise

    #
    # Common methods
    #

    def ping_worker(self):
        while True:
            time.sleep(self.ping_delay)
            current_time = time.time()

            if self.remote_side_is_down:
                log.debug('Remote side is down, exiting...')
                return

            if current_time - self.last_ping > self.relay_timeout:
                log.error('No response from the client for {0} seconds. '
                          'Restarting relay...'.format(self.relay_timeout))
                self.command_socket.close()
                return

            try:
                self.send_proxy_cmd(relay.PING_CMD)
            except socket.error as err:
                (code, msg) = err.args
                log.debug('{0} {1}. Closing socket...'.format(code, msg))
                self.command_socket.close()

            except RelayMainError as err:
                log.debug('{}. Exiting...'.format(err))
                self.shutdown()

    def generate_channel_id(self):
        channel_ids = self.channels.keys()

        while True:
            rint = random.randint(1, 65535)
            if rint not in channel_ids:
                return rint

    def set_channel(self, sock):
        """
        @return: id of the new channel
        """
        return self._set_channel(sock, self.generate_channel_id())

    #
    # Handle commands
    #

    def close_channel_hdl(self, channel_id):
        log.debug('[channel {0}] Closing...'.format(channel_id))

        if channel_id not in self.channels:
            log.warning('[channel {0}] Channel already closed'.format(channel_id))
            return

        sock_to_close = self.channels[channel_id]
        self.input_connections.remove(sock_to_close)
        self.unset_channel(channel_id)
        sock_to_close.close()

    def forward_connection_success_hdl(self, channel_id):
        if channel_id not in self.channels:
            log.debug('[channel {}] Forward connection successful. '
                      'But channel already closed'.format(channel_id))
            return

        log.debug('[channel {}] Forward connection successful. Sending success replay...'.format(channel_id))

        try:
            self.channels[channel_id].send(relay.socks_server_reply_success)
        except socket.error as err:
            (code, msg) = err.args
            log.error('[channel {}] Socket error on replying SUCCESS to a SOCKS client. '
                      'Code {}. Msg {}'.format(channel_id, code, msg))
            log.debug('[channel {0}] Closing connection and sending channel close cmd to remote side')
            sock = self.channels[channel_id]
            self.input_connections.remove(sock)
            self.unset_channel(channel_id)

            try:
                sock.close()
            except socket.error:
                log.debug('[channel {}] Error on closing socket'.format(channel_id))

            self.send_proxy_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)

    def forward_connection_failue_hdl(self, channel_id):
        if channel_id not in self.channels:
            log.warning('[channel {}] Channel already closed'.format(channel_id))
            return

        log.debug('[channel {}] Forward connection failed. Sending fail replay...'.format(channel_id))
        sock = self.channels[channel_id]
        try:
            sock.send(relay.socks_server_reply_fail)
        except socket.error as err:
            (code, msg) = err.args
            log.error('[channel {}] Socket error on replying FAILURE to a SOCKS client. '
                      'Code {}. Msg {}'.format(channel_id, code, msg))

        self.input_connections.remove(sock)
        self.unset_channel(channel_id)
        try:
            sock.close()
        except socket.error as err:
            (code, msg) = err.args
            log.debug('channel {}] Error on closing socket: Code {}. Msg {}'.format(channel_id, code, msg))

    def ping_command_hdl(self):
        self.last_ping = time.time()

    #
    # SOCKS client's methods
    #

    def handle_new_socks_connection(self, sock):
        """
        @return:
        @raise: RelayMainError
        """
        log.debug('Setting up a new connection with a client program')

        try:
            # Getting socks header from a client program
            data = sock.recv(9)
            if len(data) != 9 or b(data[-1]) != b'\x00':
                raise RelayMainError('Corrupted header: {}'.format(data))

        except socket.error as err:
            (code, msg) = err.args
            raise RelayMainError('Socket error: {} {}'.format(errno.errorcode[code], msg))

        if len(data) == 0:
            raise RelayMainError('SOCKS client prematurely ended connection')

        return self.parse_socks_header(data)

    #
    # ...
    #

    def main_loop(self):

        self.input_connections.append(self.server)

        while True:
            time.sleep(relay.delay)

            try:
                log.debug("Active channels: {0}".format(ls(self.channels.keys())))
                ready_to_read, _, _ = select.select(self.input_connections, [], [])
            except socket.error as err:
                (code, msg) = err.args
                raise RelayMainError('Socket error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))

            except KeyboardInterrupt:
                log.debug('SIGINT received. Closing relay and exiting...')
                self.shutdown()
                sys.exit(1)

            # Running over sockets from self.input_connections that have something to read from
            for inp_sock in ready_to_read:
                if inp_sock == self.server:
                    socks_client, client_addr = self.server.accept()
                    log.info("New connection from a client program {}:{}".format(client_addr[0], client_addr[1]))
                    self.input_connections.append(socks_client)
                    self.pending_socks_clients.append(socks_client)

                elif inp_sock == self.command_socket:
                    try:
                        log.debug("Processing proxy client command...")
                        self.manage_proxy_socket()
                    except Exception as err:
                        log.error(err)
                        log.warning('Closing connection with remote side and exiting loop')
                        self.shutdown()
                        return

                elif inp_sock in self.pending_socks_clients:
                    self.pending_socks_clients.remove(inp_sock)
                    try:
                        # setting up a connection with a client program
                        ip, port = self.handle_new_socks_connection(inp_sock)
                    except RelayMainError as err:
                        log.error('Error while openning a connection with a client program: {}'.format(err))
                        log.debug("Closing SOCKS client connection {0}".format(inp_sock))
                        self.input_connections.remove(inp_sock)
                        inp_sock.close()
                        continue

                    new_channel_id = self.set_channel(inp_sock)
                    log.debug('Sending command to a proxy client to open a channel {0} '
                              'for a new client program'.format(new_channel_id))
                    self.send_proxy_cmd(relay.CHANNEL_OPEN_CMD, new_channel_id, ip, port)

                elif inp_sock in self.id_by_socket:
                    self.manage_socks_client_socket(inp_sock)

                else:
                    log.debug('Active socket {0} does not belong to any channel. Closing it'.format(inp_sock))
                    inp_sock.close()


def run_server(host, port, proxy_host, proxy_port):
    log.info('============ Start proxy server ============')

    while True:
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            serversock.bind((host, port))
            serversock.listen(5)
        except socket.error:
            log.error('Exception binding socket at {0}:{1}'.format(host, port))
            time.sleep(1)
            break

        try:
            (backconnect, address) = serversock.accept()
        except KeyboardInterrupt:
            log.error('SIGINT received. Shutting down')
            sys.exit(1)

        log.info('New connection from client {0}:{1}'.format(address[0], address[1]))
        serversock.close()

        try:
            banner_rcv = backconnect.recv(4096)
            if banner_rcv != relay.banner:
                log.error("Wrong banner {0} from the client. Closing connection".format(repr(banner_rcv)))
                backconnect.close()
                continue
            backconnect.send(relay.banner_response)
        except socket.error as err:
            (code, msg) = err.args
            log.error('Caught socket error trying to establish connection with RPIVOT client. '
                      'Code {0}. Msg {1}'.format(code, msg))
            continue

        try:
            server = RelayServer(proxy_host, int(proxy_port), backconnect)

        except socket.error:
            log.error('Error on running relay server. Restarting...')
            continue
        try:
            server.main_loop()
        except RelayMainError as err:
            log.error('Got RelayError in server.main_loop(): {}'.format(err))
            log.info('Restarting relay...')
            server.server.close()
            continue

        except KeyboardInterrupt:
            log.error("Ctrl C - Stopping server...")
            sys.exit(1)


def main():
    global log

    parser = optparse.OptionParser(description='Reverse socks server')
    parser.add_option('--server-ip', action="store", dest='server_ip', default='0.0.0.0')
    parser.add_option('--server-port', action="store", dest='server_port', default='9999')
    parser.add_option('--proxy-ip', action="store", dest='proxy_ip', default='127.0.0.1')
    parser.add_option('--proxy-port', action="store", dest='proxy_port', default='1080')
    parser.add_option('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_option('--logfile', action="store", dest="logfile", default=None)

    cmd_options = parser.parse_args()[0]

    log = create_logger(__name__, True, cmd_options.verbose, cmd_options.logfile)
    run_server(cmd_options.server_ip, int(cmd_options.server_port), cmd_options.proxy_ip, int(cmd_options.proxy_port))


if __name__ == "__main__":
    main()
