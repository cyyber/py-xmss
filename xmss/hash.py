import sys
from hashlib import shake_128, shake_256, sha256

from xmss.eHashFunctions import EHashFunction
from xmss.hashAddress import setKeyAndMask
from xmss.misc import toByte


def addrToByte(byteData: list[int], addr: list[int]) -> list[int]:
    if sys.byteorder == 'little':
        for i in range(8):
            byteData[i*4:i*4+4] = toByte(addr[i], 4)
        return byteData
    else:
        return addr[:]


def coreHash(hashFunc: EHashFunction, hashType, key, keyLen, inputData, inputDataLen, n) -> bytes:
    buf = [0] * (inputDataLen + n + keyLen)

    # Input is (toByte(X, 32) || KEY || M)

    # set toByte
    buf[:n] = toByte(hashType, n)

    for i in range(keyLen):
        buf[i + n] = key[i]

    for i in range(inputDataLen):
        buf[keyLen + n + i] = inputData[i]

    if hashFunc == EHashFunction.SHAKE_128:
        hasher = shake_128()
        hasher.update(bytes(buf[:inputDataLen + keyLen + n]))
        if n == 32:
            return hasher.digest(n)
        if n == 64:
            return hasher.digest(n)

    if hashFunc == EHashFunction.SHAKE_256:
        hasher = shake_256()
        hasher.update(bytes(buf[:inputDataLen + keyLen + n]))
        if n == 32:
            return hasher.digest(n)
        if n == 64:
            return hasher.digest(n)

    if hashFunc == EHashFunction.SHA2_256:
        hasher = sha256()
        hasher.update(bytes(buf[:inputDataLen + keyLen + n]))
        if n == 32:
            return hasher.digest()

    raise Exception("Invalid hash function or wots parameter")


def prf(hashFunc: EHashFunction, inputData, key, keyLen) -> bytes:
    return coreHash(hashFunc, 3, key, keyLen, inputData, 32, keyLen)


def hMsg(hashFunc: EHashFunction, inputData, inLen, key, keyLen, n) -> bytes:
    if keyLen != 3 * n:
        raise Exception("H_msg takes 3n-bit keys, we got n={} but a keylength of {}.".format(n, keyLen))
    return coreHash(hashFunc, 2, key, keyLen, inputData, inLen, n)


def hashH(hashFunc: EHashFunction, inputData, pubSeed, addr, n) -> bytes:
    buf = [0] * (2 * n)
    bitmask = [0] * (2 * n)
    byteAddr = [0] * 32

    setKeyAndMask(addr, 0)
    addrToByte(byteAddr, addr)
    key = prf(hashFunc, byteAddr, pubSeed, n)
    # Use MSB order
    setKeyAndMask(addr, 1)
    addrToByte(byteAddr, addr)
    bitmask[:n] = prf(hashFunc, byteAddr, pubSeed, n)
    setKeyAndMask(addr, 2)
    addrToByte(byteAddr, addr)
    bitmask[n:2*n] = prf(hashFunc, byteAddr, pubSeed, n)

    for i in range(2 * n):
        buf[i] = inputData[i] ^ bitmask[i]
    return coreHash(hashFunc, 1, key, n, buf, 2 * n, n)


def hashF(hashFunc: EHashFunction, inputData, pubSeed, addr, n) -> bytes:
    buf = [0] * n
    byteAddr = [0] * 32

    setKeyAndMask(addr, 0)
    addrToByte(byteAddr, addr)
    key = prf(hashFunc, byteAddr, pubSeed, n)

    setKeyAndMask(addr, 1)
    addrToByte(byteAddr, addr)
    bitmask = prf(hashFunc, byteAddr, pubSeed, n)

    for i in range(n):
        buf[i] = inputData[i] ^ bitmask[i]
    return coreHash(hashFunc, 0, key, n, buf, n, n)
