from ecdsa import SigningKey
from hashlib import sha256
import click
import sys


@click.command()
@click.argument('psbt_file', type=click.File('rb'))
@click.option('--private-key', '-k', type=click.File('rb'), required=True)
@click.option('--hex', '-h', default=False, is_flag=True)
def main(psbt_file, hex, private_key=None):
    psbt_hash = sha256(psbt_file.read()).digest()
    key = SigningKey.from_pem(private_key.read())

    # This \x04 is wrong - need to compute the real header byte, unfortunately
    # the ecdsa implementation doesnt do this for us.

    token = b'\x04' + key.sign_digest_deterministic(psbt_hash)

    if hex:
        print(token.hex())
    else:
        sys.stdout.buffer.write(token)


if __name__ == '__main__':
    main()
