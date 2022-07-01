import re
import socket
from ntlm_auth.ntlm import Ntlm
from common import create_logger, ls, Relay, RelayMainError


log = create_logger(__name__)


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

        authenticate_message = \
            ntlm_context.create_authenticate_message(user_name=self._username, domain_name=self._domain,
                                                     password=self._password, nthash=self._nthash,
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
            exit(1)
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
