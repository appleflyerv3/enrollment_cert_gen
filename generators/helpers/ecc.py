"""
Derived from Cr50 source code.
Most of these are from ChatGPT.
"""

from signer_types import *

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

def ecc_point_add(left: ECCPoint, right: ECCPoint) -> ECCPoint:
    if left is None:
        return right

    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if left == right:
        slope = ((3 * x1 * x1 + A) * pow(2 * y1, -1, P)) % P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, P)) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    return x3, y3

def ecc_scalar_multiply(scalar: int, point: ECCPoint) -> ECCPoint:
    result = None
    addend = point

    while scalar:
        if scalar & 1:
            result = ecc_point_add(result, addend)

        addend = ecc_point_add(addend, addend)
        scalar >>= 1

    return result