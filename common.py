import sys
import logging


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
