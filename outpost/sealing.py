"""libsodium sealed boxes (crypto_box_seal: X25519, XSalsa20-Poly1305), CONTRACT section 6."""

from dataclasses import dataclass

from nacl.public import PrivateKey, PublicKey, SealedBox


@dataclass(frozen=True, slots=True)
class KeyPair:
    public_key: bytes
    private_key: bytes


def new_key_pair() -> KeyPair:
    private = PrivateKey.generate()
    return KeyPair(public_key=bytes(private.public_key), private_key=bytes(private))


def seal(public_key: bytes, plaintext: bytes) -> bytes:
    return SealedBox(PublicKey(public_key)).encrypt(plaintext)


def open_sealed(private_key: bytes, sealed: bytes) -> bytes:
    """Raises nacl.exceptions.CryptoError when the box does not open with this key."""
    return SealedBox(PrivateKey(private_key)).decrypt(sealed)
