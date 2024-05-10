# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass
import re
from pathlib import Path
import io

from docopt import docopt
from nacl.public import PrivateKey

from . import __title__, __version__, PROG, header
from . import lib
from .exceptions import Crypt4GHHeaderDecryptionError, SessionKeyDecryptionError, FromUser, AlreadyInProgress
from .keys import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

C4GH_DEBUG  = os.getenv('C4GH_DEBUG', False)
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)
DEFAULT_LOG = os.getenv('C4GH_LOG', None)

__doc__ = f'''

Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   {PROG} [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>] --in <path> --out <path>... [--range <start-end>] 
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] --in <path> --out <path>... [--range <start-end>]
   {PROG} [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   {PROG} [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>] --in <path> --out <path>... [--trim]
   {PROG} [-hv] [--log <file>] split_header --sk <path> --recipient_pk <path>  --in <path> --out <path>

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key
                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt
   --in <path>            Input file
   --out <path>           Output file


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
   C4GH_DEBUG       If True, it will print (a lot of) debug information.
                    (Watch out: the output contains secrets)
 
'''

def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # if args['version']: print(version); sys.exit(0)
    # if args['help']: print(__doc__.strip()); sys.exit(0)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    # for the root logger
    logging.basicConfig(stream=sys.stderr,
                        level=logging.DEBUG if C4GH_DEBUG else logging.CRITICAL,
                        format='[%(levelname)s] %(message)s')
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            import yaml
            logging.config.dictConfig(yaml.safe_load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)
    return args


range_re = re.compile(r'([\d]+)-([\d]+)?')

def parse_range(args):
    r = args['--range']
    if not r:
        return (0, None)

    m = range_re.match(r)
    if m is None:
        raise ValueError(f"Invalid range: {args['--range']}")
    
    start, end = m.groups()  # end might be None
    start, end = int(start), (int(end) if end else None)
    span = end - start - 1 if end else None
    if not span:
        raise ValueError(f"Invalid range: {args['--range']}")
    return (start, span)

def retrieve_private_key(args, generate=False):

    seckey = args['--sk'] or DEFAULT_SK

    if generate and seckey is None: # generate a one on the fly
        sk = PrivateKey.generate()
        skey = bytes(sk)
        LOG.debug('Generating Private Key: %s', skey.hex().upper())
        return skey

    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    return get_private_key(seckeypath, cb)

def encrypt(args):
    assert( args['encrypt'] )

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args, generate=True)

    def build_recipients():
        for pk in args['--recipient_pk']:
            recipient_pubkey = os.path.expanduser(pk)
            if not os.path.exists(recipient_pubkey):
                print(f"Recipient pubkey: {recipient_pubkey}, does not exist", file=sys.stderr)
                continue
            LOG.debug("Recipient pubkey: %s", recipient_pubkey)
            yield (0, seckey, get_public_key(recipient_pubkey))

    # keys = list of (method, privkey, recipient_pubkey=None)
    # using a set now, instead of inside the generator loop
    # because we'd remove repetition in case different filenames are used for the same key
    recipient_keys = set(build_recipients()) # must have at least one, remove repetitions
    if not recipient_keys:
        raise ValueError("No Recipients' Public Key found")

    infile_path = args['--in']
    outfile_path = args['--out']
    # Ensure infile_path is a single string, not a list
    if isinstance(infile_path, list):
        infile_path = infile_path[0]
    if isinstance(outfile_path, list):
        outfile_path = outfile_path[0]

    with open(infile_path, 'rb') as infile, open(outfile_path, 'wb') as outfile:
        lib.encrypt(recipient_keys,
                    infile,
                    outfile,
                    offset = range_start,
                    span = range_span)
    

def decrypt(args):
    assert( args['decrypt'] )

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, None)] # keys = list of (method, privkey, recipient_pubkey=None)

    infile_path = args['--in']
    outfile_path = args['--out']
    # Ensure infile_path is a single string, not a list
    if isinstance(infile_path, list):
        infile_path = infile_path[0]
    if isinstance(outfile_path, list):
        outfile_path = outfile_path[0]

    with open(infile_path, 'rb') as infile, open(outfile_path, 'wb') as outfile:
        lib.decrypt(keys,
                    infile,
                    outfile,
                    offset = range_start,
                    span = range_span,
                    sender_pubkey=sender_pubkey)


def rearrange(args):
    assert( args['rearrange'] )

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, bytes(PrivateKey(seckey).public_key))] # keys = list of (method, privkey, recipient_pubkey=ourselves)

    lib.rearrange(keys,
                  sys.stdin.buffer,
                  sys.stdout.buffer,
                  offset = range_start,
                  span = range_span)

def reencrypt(args):
    assert( args['reencrypt'] )

    seckey = retrieve_private_key(args)

    def build_recipients():
        for pk in args['--recipient_pk']:
            recipient_pubkey = os.path.expanduser(pk)
            if not os.path.exists(recipient_pubkey):
                print(f"Recipient pubkey: {recipient_pubkey}, does not exist", file=sys.stderr)
                continue
            LOG.debug("Recipient pubkey: %s", recipient_pubkey)
            yield (0, seckey, get_public_key(recipient_pubkey))

    # keys = list of (method, privkey, recipient_pubkey=None)
    # using a set now, instead of inside the generator loop
    # because we'd remove repetition in case different filenames are used for the same key
    recipient_keys = set(build_recipients()) # must have at least one, remove repetitions
    if not recipient_keys:
        raise ValueError("No Recipients' Public Key found")

    infile_path = args['--in']
    outfile_path = args['--out']
    # Ensure infile_path is a single string, not a list
    if isinstance(infile_path, list):
        infile_path = infile_path[0]
    if isinstance(outfile_path, list):
        outfile_path = outfile_path[0]

    with open(infile_path, 'rb') as infile, open(outfile_path, 'wb') as outfile:
        lib.reencrypt([(0, seckey, None)], # sender_keys
                      recipient_keys,
                      infile,
                      outfile,
                      trim=args['--trim'])


def split_header(args):

    assert ( args['split_header'] )

    infile_path = args['--in']
    outfile_path = args['--out']
    # Ensure infile_path is a single string, not a list
    if isinstance(infile_path, list):
        infile_path = infile_path[0]
    if isinstance(outfile_path, list):
        outfile_path = outfile_path[0]

    LOG.info('Separating header from file: %s', infile_path)

    if not os.path.exists(infile_path):
        raise FileNotFoundError(infile_path)  # return early

    with open(infile_path, 'rb') as infile, open(outfile_path, 'wb') as outfile:  # and truncate stage file

        LOG.debug('Reading header')
        try:
            seckey = retrieve_private_key(args, generate=False)
            service_key = (0, seckey, None)  # not checking the sender
            # Get session keys
            session_keys, edit_list = header.deconstruct(infile, [service_key])
        except Exception as e:
            LOG.error('Decryption error: %r', e)
            raise Crypt4GHHeaderDecryptionError() from e

        # Raise error we could not decrypt the header (ie no session keys retrieved)
        if not session_keys:
            raise SessionKeyDecryptionError('No session keys found')

        if edit_list:
            raise FromUser('Support for Crypt4GH edit list has been removed')

        # The infile is left right at the position of the payload
        pos = infile.tell()

        # Just record the header.
        infile.seek(0, io.SEEK_SET)  # rewind to beginning (it's ok: not a stream)
        header_bytes = infile.read(pos)
        outfile.write(header_bytes)
