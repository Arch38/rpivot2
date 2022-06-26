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
