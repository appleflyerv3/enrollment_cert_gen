"""
Derived from Cr50 source code.
Most of these are from ChatGPT.
"""

import secrets

from signer_types import *

def _first_primes(count: int) -> tuple[int, ...]:
    primes = [2]
    candidate = 3

    while len(primes) < count:
        for p in primes:
            if p * p > candidate:
                primes.append(candidate)
                break
            if candidate % p == 0:
                break

        candidate += 2

    return tuple(primes)

# Replicate the PRIME_DELTAS array in bn.c
_SMALL_PRIMES = _first_primes(4096)

def miller_rabin(n: int, rounds: int = 7) -> bool:
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True

# Attempt to mirror the behavior of DCRYPTO_bn_generate_prime
def cr50_prime(
    kdf_bytes: bytes,
    exponent: int,
) -> int | None:
    bits = len(kdf_bytes) * 8

    # Cr50 DCRYPTO bignums use little-endian limbs.
    candidate = int.from_bytes(kdf_bytes, "little")

    # Set the two highest bits and the lowest bit.
    candidate |= 1
    candidate |= 1 << (bits - 1)
    candidate |= 1 << (bits - 2)

    # Represents candidate + 0, +2, ..., +4094.
    composites = bytearray(2048)

    # Apply Cr50's small-prime sieve.
    for p in _SMALL_PRIMES[1:]:
        first_index = (
            -(candidate % p) * pow(2, -1, p)
        ) % p

        for index in range(first_index, 2048, p):
            composites[index] = 1

    for index, composite in enumerate(composites):
        if composite:
            continue

        value = candidate + 2 * index

        if value % exponent >= 2 and miller_rabin(value):
            return value

    return None