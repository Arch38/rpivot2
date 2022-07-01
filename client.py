#!/usr/bin/env python

import socket
import re
import sys
import time
from struct import unpack
import select
import optparse
import errno
import relay
import threading
from ntlm_auth.ntlm import Ntlm
from common import create_logger, ls, Relay, RelayMainError


def key_by_value(my_dict, value):
    for k, v in my_dict.items():
        if v == value:
            return k
    return None


class SocksRelay(Relay):

    def __init__(self, command_socket):
        super(SocksRelay, self).__init__(command_socket)
        self.establishing_dict = {}
        self.forward_socket = None
        self.data = None

        self.ping_thread = threading.Thread(target=self.ping_worker, name='Ping')
        self.ping_thread.start()

    #
    # Common methods
    #

    def ping_worker(self):
        while True:
            time.sleep(self.ping_delay)
            current_time = time.time()

            if self.remote_side_is_down:
                log.debug('Remote side down. Exiting ping worker')
                return

            if current_time - self.last_ping > self.relay_timeout:
                log.error('No response from remote side for {0} seconds. '
                          'Restarting relay...'.format(relay.relay_timeout))
                self.command_socket.close()
                return

    def close_connection_with_server(self):
        self.command_socket.close()
        self.input_connections.remove(self.command_socket)

    #
    # Handle commands
    #

    def close_channel_hdl(self, channel_id):
        establishing_sock = key_by_value(self.establishing_dict, channel_id)
        if establishing_sock is not None:
            log.debug('[{0}] Closing establishing channel...'.format(channel_id))
            del self.establishing_dict[establishing_sock]
            return

        elif channel_id not in self.channels:
            log.debug('Channel {0} non existent'.format(channel_id))
            return

        sock_to_close = self.channels[channel_id]
        self.unset_channel(channel_id)
        log.debug('[{}] Closing channel...'.format(channel_id))
        sock_to_close.close()
        self.input_connections.remove(sock_to_close)

    def open_channel_hdl(self, data):
        channel_id, packed_ip, port = unpack('<HIH', data[1:9])
        ip = socket.inet_ntoa(data[3:7])
        log.debug('Got new channel request with id {0}. '
                  'Opening new forward connection to host {1} port {2}'.format(channel_id, ip, port))
        self.establish_forward_socket(channel_id, ip, port)

    def ping_command_hdl(self):
        self.last_ping = time.time()
        self.send_proxy_cmd(relay.PING_CMD)

    #
    # SOCKS client's methods
    #

    def establish_forward_socket(self, channel_id, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            log.debug("[{}] Opening {}:{}".format(channel_id, host, port))
            sock.connect_ex((host, port))
        except socket.error as err:
            (code, msg) = err.args
            log.error("[{}] Caught exception socket.error: {}: {}".format(channel_id, code, msg))
            self.send_proxy_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
            return

        log.debug('[{}] New pending forward connection: {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id

    #
    # ...
    #

    def run(self):
        ready_to_read = None
        ready_to_write = None

        while True:
            try:
                time.sleep(relay.delay)
                log.debug('Active channels: {0}. Pending Channels {1}'.format(
                    ls(self.channels.keys()), ls(self.establishing_dict.values())))
                ready_to_read, ready_to_write, _ = \
                    select.select(self.input_connections, self.establishing_dict.keys(), [], 15)
            except KeyboardInterrupt:
                log.info('SIGINT received. Closing relay and exiting')
                self.send_proxy_cmd(relay.CLOSE_RELAY)
                self.shutdown()
            except (select.error, socket.error) as err:
                (code, msg) = err.args
                log.error('Select error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
                self.shutdown()

            for sock in ready_to_write:
                channel_id = self.establishing_dict[sock]
                log.debug('[{0}] Establishing connection with channel id {0}'.format(channel_id))

                try:
                    sock.recv(0)
                except socket.error as err:
                    (code, err_msg) = err.args
                    if code == errno.ECONNREFUSED or code == errno.ETIMEDOUT:
                        if sock in ready_to_read:
                            ready_to_read.remove(sock)
                        del self.establishing_dict[sock]
                        self.send_proxy_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
                        sock.close()
                        continue
                    elif code == errno.EAGAIN:
                        log.debug('Recv(0) return errno.EAGAIN for socket {0} on channel {1}. '
                                  'Connection established.'.format(sock, channel_id))
                    elif code == 10035:
                        log.debug('Recv(0) raised windows-specific exception 10035. Connection established.')
                    else:
                        raise

                log.info('Connection established on channel {0}'.format(channel_id))
                sock.setblocking(1)

                self.send_proxy_cmd(relay.FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_connections.append(sock)
                self._set_channel(sock, channel_id)

            for selected_input_socket in ready_to_read:
                if selected_input_socket == self.command_socket:
                    try:
                        self.manage_proxy_socket()
                    except RelayMainError:
                        log.debug('Remote side closed socket')
                        relay.close_sockets(self.input_connections)
                        return
                else:
                    self.manage_socks_client_socket(selected_input_socket)


class NtlmProxyContext(object):
    negotiate_request = '''CONNECT {0}:{1} HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Proxy-Connection: keep-alive
Connection: keep-alive
Proxy-Authorization: NTLM {2}

'''
    authenticate_request = '''CONNECT {0}:{1} HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Proxy-Connection: keep-alive
Connection: keep-alive
Proxy-Authorization: NTLM {2}

'''

    def __init__(self, sock, proxy_ip, proxy_port, username, domain=None, password=None, nthash=None, lmhash=None):
        self._sock = sock
        self._proxy_ip = proxy_ip
        self._proxy_port = proxy_port
        self._username = username
        self._password = password
        self._nthash = nthash
        self._lmhash = lmhash
        self._domain = domain
        self._workstation = socket.gethostname().upper()

    def connect(self, host_port):
        (host, port) = host_port
        ntlm_context = Ntlm(ntlm_compatibility=5)
        negotiate_message = ntlm_context.create_negotiate_message(self._domain, self._workstation).decode()
        resp = None
        try:
            self._sock.connect((self._proxy_ip, self._proxy_port))
            self._sock.send(NtlmProxyContext.negotiate_request.format(host, str(port), negotiate_message))
            resp = self._sock.recv(4096)
        except socket.error as err:
            (code, msg) = err.args
            log.error("Caught socket error trying to establish connection to proxy. "
                      "Code {0}. Msg {1}".format(code, msg))
            raise

        try:
            chal_msg = NtlmProxyContext.get_challenge(resp)
            ntlm_context.parse_challenge_message(chal_msg)
        except TypeError as err:
            (code, msg) = err.args
            log.error("Couldn't parse proxy challenge. Code {0}. Msg {1}".format(code, msg))
            if resp is not None:
                log.error("Challenge contents: {0}".format(resp))
            else:
                log.error("Challenge contents is 'None'")
            self._sock.close()

        authenticate_message = ntlm_context.create_authenticate_message(user_name=self._username,
                                                                        domain_name=self._domain,
                                                                        password=self._password,
                                                                        nthash=self._nthash,
                                                                        lmhash=self._lmhash).decode()
        resp = None
        try:
            self._sock.send(NtlmProxyContext.authenticate_request.format(host, str(port), authenticate_message))
            resp = self._sock.recv(4096)
        except socket.error as err:
            (code, msg) = err.args
            log.error('Caught socket error trying to send challenge response connection to proxy. '
                      'Code {0}. Msg {1}'.format(code, msg))
            self._sock.close()
            raise

        if resp is None:
            log.error("Received an empty response to the challenge response")
            self._sock.close()

        if b'HTTP/1.1 200 Connection established' in resp:
            log.info('Ntlm proxy established connection')
            log.debug(resp)
        elif b'HTTP/1.1 503 Service Unavailable' in resp:
            log.error('Ntlm proxy response: Service Unavailable')
            log.debug(resp)
            self._sock.close()
        elif b'HTTP/1.1 407 Proxy Authentication Required' in resp:
            log.error('Ntlm proxy authentication failed')
            log.debug(resp)
            self._sock.close()
            sys.exit(1)
        else:
            log.error('Ntlm proxy unknown error')
            log.debug(resp)
            self._sock.close()

    def __getattr__(self, attribute_name):
        """Defer unknown behaviour to the socket"""
        return getattr(self._sock, attribute_name)

    @staticmethod
    def get_challenge(raw_msg):
        if raw_msg is None:
            return None
        re_res = re.search(r'^Proxy-Authenticate: NTLM (.*)$', raw_msg, re.MULTILINE)
        if re_res is None:
            return None
        else:
            return re_res.group(1)


def main():
    global log

    parser = optparse.OptionParser(description='Reverse socks client')
    parser.add_option('--server-ip', action="store", dest='server_ip')
    parser.add_option('--server-port', action="store", dest='server_port', default='9999')
    parser.add_option('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_option('--logfile', action="store", dest="logfile", default=None)

    proxy_group = optparse.OptionGroup(parser, 'Ntlm Proxy authentication')

    proxy_group.add_option('--ntlm-proxy-ip', dest='ntlm_proxy_ip', default=None, action='store',
                           help='IP address of NTLM proxy')
    proxy_group.add_option('--ntlm-proxy-port', dest='ntlm_proxy_port', default=None, action='store',
                           help='Port of NTLM proxy')
    proxy_group.add_option('--username', dest='username', default='', action='store',
                           help='Username to authenticate with NTLM proxy')
    proxy_group.add_option('--domain', dest='domain', default='', action='store',
                           help='Domain to authenticate with NTLM proxy')
    proxy_group.add_option('--password', dest='password', default='', action='store',
                           help='Password to authenticate with NTLM proxy')
    proxy_group.add_option('--hashes', dest='hashes', default=None, action='store',
                           help='Hashes to authenticate with instead of password. Format - LMHASH:NTHASH')

    parser.add_option_group(proxy_group)

    cmd_options = parser.parse_args()[0]
    if cmd_options.server_ip is None:
        print('Server IP required')
        sys.exit()

    log = create_logger(__name__, True, cmd_options.verbose, cmd_options.logfile)

    log.info('============ Start proxy client ============')

    while True:
        log.info('Backconnecting to server {0} port {1}'.format(cmd_options.server_ip, cmd_options.server_port))
        backconnect_host = cmd_options.server_ip
        backconnect_port = int(cmd_options.server_port)
        bc_sock = None

        while True:
            try:
                bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if cmd_options.ntlm_proxy_ip is not None:
                    if cmd_options.ntlm_proxy_port is None:
                        log.error('Error. Must specify ntlm proxy port')
                        sys.exit(1)
                    if cmd_options.hashes is not None:
                        if re.match('[a-zA-Z0-9]{32}:[a-zA-Z0-9]{32}', cmd_options.hashes) is None:
                            log.error('Hash format error. Valid hash format - LMHASH:NTHASH')
                            sys.exit(1)

                    log.info('Connecting via NTLM proxy at {0}:{1}'.format(
                        cmd_options.ntlm_proxy_ip, cmd_options.ntlm_proxy_port))

                    ntlm_con = NtlmProxyContext(
                        bc_sock,
                        proxy_ip=cmd_options.ntlm_proxy_ip,
                        proxy_port=int(cmd_options.ntlm_proxy_port),
                        username=cmd_options.username,
                        domain=cmd_options.domain,
                        password=cmd_options.password,
                        nthash=None if cmd_options.hashes is None else cmd_options.hashes.split(':')[1],
                        lmhash=None if cmd_options.hashes is None else cmd_options.hashes.split(':')[0])

                    bc_sock = ntlm_con

                bc_sock.connect((backconnect_host, backconnect_port))
                break
            except socket.error as err:
                (code, msg) = err.args
                log.error('Unable to connect to {0}:{1}. Caught socket error trying to establish '
                          'connection with RPIVOT server. Code {2}. Msg {3}. '
                          'Retrying...'.format(cmd_options.server_ip, cmd_options.server_port, code, msg))
                time.sleep(5)

        try:
            bc_sock.send(relay.banner)
            banner_reponse_rcv = bc_sock.recv(4096)
            if banner_reponse_rcv != relay.banner_response:
                log.error("Wrong banner response {0} from server. Retrying".format(repr(banner_reponse_rcv)))
                bc_sock.close()
                time.sleep(5)
                continue
        except socket.error as err:
            (code, msg) = err.args
            log.error('Caught socket error trying to establish connection with RPIVOT server. '
                      'Code {0}. Msg {1}'.format(code, msg))
            bc_sock.close()
            time.sleep(5)
            continue

        socks_relayer = SocksRelay(bc_sock)
        try:
            socks_relayer.run()
        except socket.error as err:
            (code, msg) = err.args
            log.error('Exception in socks_relayer.run(). '
                      'Errno: {0} Msg: {1}. Restarting relay...'.format(errno.errorcode[code], msg))
            bc_sock.close()
            continue

        time.sleep(10)


if __name__ == '__main__':
    main()
