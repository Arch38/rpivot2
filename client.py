#!/usr/bin/env python

import logging
import logging.handlers
import socket
import sys
import time
from struct import pack, unpack
import select
import optparse
import errno
import relay
import threading
from ntlm_auth.ntlm import Ntlm
import re


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


def key_by_value(my_dict, value):
    for k, v in my_dict.iteritems():
        if v == value:
            return k
    return None


class SocksRelay:
    STATUS_SUCCESS = 0
    STATUS_REFUSED = 1
    STATUS_TIMEOUT = 2

    def __init__(self, bc_sock):
        self.channel = {}
        self.id_by_socket = {}
        self.bc_sock = bc_sock
        self.input_list = [self.bc_sock]
        self.establishing_dict = {}
        self.forward_socket = None
        self.data = None
        self.last_ping_time = time.time()

        logger.debug('Starting ping thread')

        self.ping_thread = threading.Thread(target=self.ping_worker, name='Ping')

        self.ping_thread.start()
        self.remote_side_down = False

    def ping_worker(self):
        while True:
            time.sleep(10)
            current_time = time.time()

            if self.remote_side_down:
                logger.debug('Remote side down. Exiting ping worker')
                return

            if current_time - self.last_ping_time > relay.relay_timeout:
                logger.error('No response from remote side for {0} seconds. '
                             'Restarting relay...'.format(relay.relay_timeout))
                self.bc_sock.close()
                return

    def shutdown(self):
        self.remote_side_down = True
        relay.close_sockets(self.input_list)
        sys.exit(1)

    def run(self):
        inputready = None
        outputready = None

        while True:
            try:
                time.sleep(relay.delay)
                logger.debug('Active channels: {0}. '
                             'Pending Channels {1}'.format(self.channel.keys(), self.establishing_dict.values()))
                inputready, outputready, _ = select.select(self.input_list, self.establishing_dict.keys(), [], 15)
            except KeyboardInterrupt:
                logger.info('SIGINT received. Closing relay and exiting')
                self.send_remote_cmd(relay.CLOSE_RELAY)
                self.shutdown()
            except (select.error, socket.error) as (code, msg):
                logger.debug('Select error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
                self.shutdown()

            for sock in outputready:
                channel_id = self.establishing_dict[sock]
                logger.debug('Establishing connection with channel id {0}'.format(channel_id))

                try:
                    sock.recv(0)
                except socket.error as (code, err_msg):
                    if code == errno.ECONNREFUSED or code == errno.ETIMEDOUT:
                        logger.debug('Connection {0}'.format(errno.errorcode[code]))
                        if sock in inputready:
                            inputready.remove(sock)
                        del self.establishing_dict[sock]
                        self.send_remote_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
                        sock.close()
                        continue
                    elif code == errno.EAGAIN:
                        logger.debug('Recv(0) return errno.EAGAIN for socket {0} on channel {1}. '
                                     'Connection established.'.format(sock, channel_id))
                    elif code == 10035:
                        logger.debug('Recv(0) raised windows-specific exception 10035. Connection established.')
                    else:
                        raise

                logger.info('Connection established on channel {0}'.format(channel_id))
                sock.setblocking(1)

                self.send_remote_cmd(relay.FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_list.append(sock)
                self.set_channel(sock, channel_id)

            for selected_input_socket in inputready:
                if selected_input_socket == self.bc_sock:
                    try:
                        self.manage_remote_socket()
                    except relay.RelayError:
                        logger.debug('Remote side closed socket')
                        relay.close_sockets(self.input_list)
                        return
                else:
                    self.manage_forward_socket(selected_input_socket)

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received command data from remote side. Cmd: {0}'.format(relay.cmd_names[cmd]))

        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Channel close request with id: {0}'.format(channel_id))
            establishing_sock = key_by_value(self.establishing_dict, channel_id)

            if establishing_sock is not None:
                logger.debug('Closing establishing socket with id: {0}'.format(channel_id))
                del self.establishing_dict[establishing_sock]

            elif channel_id not in self.channel:
                logger.debug('Channel {0} non existent'.format(channel_id))
                return

            else:
                sock_to_close = self.channel[channel_id]
                self.unset_channel(channel_id)
                logger.debug('Closing socket with id: {0}'.format(channel_id))
                sock_to_close.close()
                self.input_list.remove(sock_to_close)

        elif cmd == relay.CHANNEL_OPEN_CMD:
            logger.debug('Data on channel id: {0}'.format(data.encode('hex')))
            channel_id, packed_ip, port = unpack('<HIH', data[1:9])
            ip = socket.inet_ntoa(data[3:7])  # ERROR HAPPENS HERE
            logger.debug('Got new channel request with id {0}. '
                         'Opening new forward connection to host {1} port {2}'.format(channel_id, ip, port))
            self.establish_forward_socket(channel_id, ip, port)

        elif cmd == relay.CLOSE_RELAY:
            logger.info('Got command to close relay. Closing socket and exiting.')
            self.shutdown()

        elif cmd == relay.PING_CMD:
            self.last_ping_time = time.time()
            self.send_remote_cmd(relay.PING_CMD)

        else:
            logger.debug('Received unknown cmd: {0}'.format(cmd))

    def get_channel_data(self):
        try:
            tlv_header = relay.recvall(self.bc_sock, 4)
            channel_id, tlv_data_len = unpack('<HH', tlv_header)
            data = relay.recvall(self.bc_sock, tlv_data_len)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving tlv message from remote side. Exiting')
            logger.debug('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            raise relay.RelayError

        return channel_id, data

    def manage_remote_socket(self):
        try:
            (channel_id, data) = self.get_channel_data()
        except relay.RelayError:
            logger.debug('Exiting!')
            self.close_remote_connection()
            raise relay.RelayError

        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            logger.debug('Got data to relay from remote side. Channel id {0}. '
                         'Data length: {1}'.format(channel_id, len(data)))
            self.relay(data, relay_to_sock)
        else:
            logger.debug('Relay from socket {0} with channel {1} not possible. '
                         'Channel does not exist'.format(self.bc_sock, channel_id))
            return

    def close_remote_connection(self):
        self.bc_sock.close()
        self.input_list.remove(self.bc_sock)

    def manage_forward_socket(self, sock):
        if sock not in self.id_by_socket:
            logger.debug('Channel corresponding to remote socket {0} already closed. '
                         'Closing forward socket'.format(sock))
            return
        channel_id = self.id_by_socket[sock]
        # logger.debug('Readable socket {0} with channel id {1}'.format(sock, channel_id))
        try:
            data = sock.recv(relay.buffer_size)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving data from socket {0} with channel id {1}'.format(sock, channel_id))
            logger.debug('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            logger.debug('Closing socket {0} with channel id {1}'.format(sock, channel_id))
            self.close_forward_connection(sock)
            return
        data_len = len(data)
        if data_len == 0:
            self.close_forward_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<HH', channel_id, len(data))
            logger.debug('Got data to relay from app side. Channel id {0}. '
                         'Data length: {1}'.format(channel_id, len(data)))
            logger.debug('Preparing tlv header: {0}'.format(tlv_header.encode('hex')))
            logger.debug('Data contents: {0}'.format(data.encode('hex')))
            self.relay(tlv_header + data, self.bc_sock)

    def close_forward_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing forward socket {0} with id {1}'.format(sock, channel_id))
        logger.debug('Current remote side socket: {0}'.format(self.bc_sock))
        logger.debug('Notifying remote side')
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)

    def send_remote_cmd(self, cmd, *args):
        logger.debug('Sending command to server: {0}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        else:
            cmd_buffer = cmd
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        try:
            self.bc_sock.send(tlv_header + cmd_buffer)
        except socket.error as (code, cmd):
            logger.error('Socket error on sending command to remote side. Code {0}. Msg {1}'.format(code, cmd))

    def set_channel(self, sock, channel_id):
        self.channel[channel_id] = sock
        self.id_by_socket[sock] = channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]

    def establish_forward_socket(self, channel_id, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            logger.debug("[channel {}] Opening {} : {}".format(channel_id, host, port))
            sock.connect_ex((host, port))
        except socket.error as (code, msg):
            logger.error("[channel {}] Caught exception socket.error during establishing forward connection. "
                         "Code {}. Msg {}".format(channel_id, code, msg))
            self.send_remote_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
            return

        logger.debug('[channel {}] Adding new pending forward connection with socket {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id

    def relay(self, data, to_socket):
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as (code, msg):
            logger.debug('Exception on relaying data to socket {}. '
                         'Errno: {} Msg: {}'.format(to_socket, errno.errorcode[code], msg))
            if to_socket == self.bc_sock:
                raise relay.RelayError
            else:
                channel_id = self.id_by_socket[to_socket]
                logger.debug('[channel {}] Closing socket...'.format(channel_id))
                to_socket.close()
                self.input_list.remove(to_socket)
                self.unset_channel(channel_id)
                self.send_remote_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)


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
        except socket.error as (code, msg):
            logger.error("Caught socket error trying to establish connection to proxy. "
                         "Code {0}. Msg {1}".format(code, msg))
            raise

        try:
            chal_msg = NtlmProxyContext.get_challenge(resp)
            ntlm_context.parse_challenge_message(chal_msg)
        except TypeError as (code, msg):
            logger.error("Couldn't parse proxy challenge. Code {0}. Msg {1}".format(code, msg))
            if resp is not None:
                logger.error("Challenge contents: {0}".format(resp))
            else:
                logger.error("Challenge contents is 'None'")
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
        except socket.error as (code, msg):
            logger.error("Caught socket error trying to send challenge response connection to proxy. "
                         "Code {0}. Msg {1}".format(code, msg))
            self._sock.close()
            raise

        if resp is None:
            logger.error("Received an empty response to the challenge response")
            self._sock.close()

        if 'HTTP/1.1 200 Connection established' in resp:
            logger.info('Ntlm proxy established connection')
            logger.debug(resp)
        elif 'HTTP/1.1 503 Service Unavailable' in resp:
            logger.error('Ntlm proxy response: Service Unavailable')
            logger.debug(resp)
            self._sock.close()
        elif 'HTTP/1.1 407 Proxy Authentication Required' in resp:
            logger.error('Ntlm proxy authentication failed')
            logger.debug(resp)
            self._sock.close()
            sys.exit(1)
        else:
            logger.error('Ntlm proxy unknown error')
            logger.debug(resp)
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
    global logger

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
        print 'Server IP required'
        sys.exit()

    logger = create_logger(__name__, True, cmd_options.verbose, cmd_options.logfile)

    logger.info('============ Start proxy client ============')

    while True:
        logger.info('Backconnecting to server {0} port {1}'.format(cmd_options.server_ip, cmd_options.server_port))
        backconnect_host = cmd_options.server_ip
        backconnect_port = int(cmd_options.server_port)
        bc_sock = None

        while True:
            try:
                bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if cmd_options.ntlm_proxy_ip is not None:
                    if cmd_options.ntlm_proxy_port is None:
                        logger.error('Error. Must specify ntlm proxy port')
                        sys.exit(1)
                    if cmd_options.hashes is not None:
                        if re.match('[a-zA-Z0-9]{32}:[a-zA-Z0-9]{32}', cmd_options.hashes) is None:
                            logger.error('Hash format error. Valid hash format - LMHASH:NTHASH')
                            sys.exit(1)

                    logger.info('Connecting via NTLM proxy at {0}:{1}'.format(
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
            except socket.error as (code, msg):
                logger.error('Unable to connect to {0}:{1}. Caught socket error trying to establish '
                             'connection with RPIVOT server. Code {2}. Msg {3}. '
                             'Retrying...'.format(cmd_options.server_ip, cmd_options.server_port, code, msg))
                time.sleep(5)

        try:
            bc_sock.send(relay.banner)
            banner_reponse_rcv = bc_sock.recv(4096)
            if banner_reponse_rcv != relay.banner_response:
                logger.error("Wrong banner response {0} from server. Retrying".format(repr(banner_reponse_rcv)))
                bc_sock.close()
                time.sleep(5)
                continue
        except socket.error as (code, msg):
            logger.error('Caught socket error trying to establish connection with RPIVOT server. '
                         'Code {0}. Msg {1}'.format(code, msg))
            bc_sock.close()
            time.sleep(5)
            continue

        socks_relayer = SocksRelay(bc_sock)
        try:
            socks_relayer.run()
        except socket.error as (code, msg):
            logger.error('Exception in socks_relayer.run(). Restarting relay...')
            logger.error('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            bc_sock.close()
            continue

        time.sleep(10)


if __name__ == '__main__':
    main()
