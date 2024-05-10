##############################################################
##
##    Decorator for Error Handling
##
##############################################################

import sys
import logging
import errno

from nacl.exceptions import (InvalidkeyError,
                             BadSignatureError,
                             CryptoError)

LOG = logging.getLogger(__name__)


class FromUser(Exception):
    """Raised Exception on incorrect user input."""

    def __str__(self):  # Informal description
        """Return readable informal description."""
        return 'Incorrect user input'

    def __repr__(self):  # Technical description
        """Return detailed, technical description."""
        return str(self)


class AlreadyInProgress(Warning):
    """Raised when a file is already in progress."""

    def __init__(self, path):
        self.path = path

    def __repr__(self):
        return f'Warning: File already in progress or existing: {self.path}'

def convert_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (InvalidkeyError, BadSignatureError, CryptoError) as e:
            LOG.error('Converting Crypto errors')
            raise ValueError('Crypt4GH Crypto Error') from e
    return wrapper

def close_on_broken_pipe(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (IOError) as e:
            if e.errno == errno.EPIPE:
                LOG.error('Closing on Broken Pipe')
            # raise ValueError(f'Crypt4GH Error: {e}') from e
    return wrapper

def exit_on_invalid_passphrase(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except CryptoError as e:
            LOG.error('Exiting for %r', e)
            print('Invalid Key or Passphrase', file=sys.stderr)
            sys.exit(2)
    return wrapper


class Crypt4GHHeaderDecryptionError(FromUser):
    """Raised Exception when header decryption fails."""

    def __str__(self):
        return 'Error decrypting this Crypt4GH file'


class SessionKeyDecryptionError(FromUser):
    """Raised Exception when header decryption fails."""

    def __init__(self, h):
        self.header = h.hex().upper()

    def __str__(self):
        return 'Unable to decrypt header with master key'

    def __repr__(self):
        return f'Unable to decrypt header with master key: {self.header}'