from xmss.eHashFunctions import EHashFunction
from xmss.hash import hashH, hMsg
from xmss.hashAddress import setTreeHeight, setTreeIndex, setType, setOTSAdrs, setLTreeAdrs
from xmss.wots import wotsPKFromSig
from xmss.misc import toByte


def lTree(hashFunc, params, leaf, wotsPk, pubSeed, addr):
    l = params.len
    n = params.n
    height = 0

    setTreeHeight(addr, height)

    while l > 1:
        bound = l >> 1
        for i in range(bound):
            setTreeIndex(addr, i)
            wotsPk[i * n:(i + 1) * n] = hashH(hashFunc, wotsPk[i * 2 * n:], pubSeed, addr, n)
        if l & 1:
            wotsPk[(l >> 1) * n:(l >> 1) * n + n] = wotsPk[(l - 1) * n:(l - 1) * n + n]
            l = (l >> 1) + 1
        else:
            l = (l >> 1)
        height += 1
        setTreeHeight(addr, height)

    leaf[:n] = wotsPk[:n]


def validateAuthpath(hashFunc, root, leaf, leafIdx, authpath, n, h, pubSeed, addr):
    buffer = [0] * (2 * n)

    # If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
    # Otherwise, it is the other way around
    if leafIdx & 1:
        for j in range(n):
            buffer[n + j] = leaf[j]
        for j in range(n):
            buffer[j] = authpath[j]
    else:
        for j in range(n):
            buffer[j] = leaf[j]
        for j in range(n):
            buffer[n + j] = authpath[j]
    authpath = authpath[n:]

    for i in range(h - 1):
        setTreeHeight(addr, i)
        leafIdx >>= 1
        setTreeIndex(addr, leafIdx)
        if leafIdx & 1:
            buffer[n:2 * n] = hashH(hashFunc, buffer, pubSeed, addr, n)
            for j in range(n):
                buffer[j] = authpath[j]
        else:
            buffer[:n] = hashH(hashFunc, buffer, pubSeed, addr, n)
            for j in range(n):
                buffer[n + j] = authpath[j]
        authpath = authpath[n:]
    setTreeHeight(addr, h - 1)
    leafIdx >>= 1
    setTreeIndex(addr, leafIdx)
    root[:n] = hashH(hashFunc, buffer, pubSeed, addr, n)


def xmssVerifySig(hashFunc: EHashFunction, wotsParams, msg, msglen, sigMsg, pk, h):
    sigMsgLen = 4 + 32 + wotsParams.len * 32 + h * 32
    n = wotsParams.n

    wotsPK = bytearray(wotsParams.keySize)
    pkHash = bytearray(n)
    root = bytearray(n)
    msgH = bytearray(n)
    hashKey = bytearray(3 * n)

    pubSeed = bytearray(n)
    pubSeed[:n] = pk[n:]

    otsAddr = [0, 0, 0, 0, 0, 0, 0, 0]
    lTreeAddr = [0, 0, 0, 0, 0, 0, 0, 0]
    nodeAddr = [0, 0, 0, 0, 0, 0, 0, 0]

    setType(otsAddr, 0)
    setType(lTreeAddr, 1)
    setType(nodeAddr, 2)

    idx = (sigMsg[0] << 24) | (sigMsg[1] << 16) | (sigMsg[2] << 8) | sigMsg[3]

    hashKey[:n] = sigMsg[4:4+n]
    hashKey[n:2*n] = pk
    hashKey[2*n:2*n+n] = toByte(idx, n)

    sigMsg = sigMsg[n+4:]
    sigMsgLen -= (n + 4)

    msgH[:n] = hMsg(hashFunc, msg, msglen, hashKey, 3*n, n)

    setOTSAdrs(otsAddr, idx)
    wotsPKFromSig(hashFunc, wotsPK, sigMsg, msgH, wotsParams, pubSeed, otsAddr)

    sigMsg = sigMsg[wotsParams.keySize:]
    sigMsgLen -= wotsParams.keySize

    setLTreeAdrs(lTreeAddr, idx)
    lTree(hashFunc, wotsParams, pkHash, wotsPK, pubSeed, lTreeAddr)

    validateAuthpath(hashFunc, root, pkHash, idx, sigMsg, n, h, pubSeed, nodeAddr)

    sigMsg = sigMsg[h*n:]
    sigMsgLen -= h*n

    for i in range(n):
        if root[i] != pk[i]:
            for i in range(sigMsgLen):
                msg[i] = 0
            return -1

    for i in range(sigMsgLen):
        msg[i] = sigMsg[i]

    return 0
