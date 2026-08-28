from dataclasses import dataclass

@dataclass(frozen=True)
class RSAKeyPair:
    n: int # public modulus
    e: int # public exponent
    
    d: int # private exponent
    p: int # private prime 1
    q: int # private prime 2

@dataclass(frozen=True)
class ECCKeyPair:
    d: int # private integer
    x: int # public key x coord
    y: int # public key y coord
    counter: int # key state

    @property
    def private_bytes(self) -> bytes:
        return self.d.to_bytes(32, "big")

    @property
    def public_bytes(self) -> bytes:
        # SEC1 uncompressed P-256 point.
        return (
            b"\x04"
            + self.x.to_bytes(32, "big")
            + self.y.to_bytes(32, "big")
        )

ECCPoint = tuple[int, int] | None