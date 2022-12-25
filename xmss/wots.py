from xmss.eHashFunctions import EHashFunction
from xmss.hash import prf, hashF
from xmss.hashAddress import setHashAdrs, setChainAdrs
from xmss.misc import toByte
from xmss.wotsParams import WOTSParams


def expandSeed(hashFunc: EHashFunction, outseeds, inseed, n, l):
    ctr = [0] * 32
    for i in range(l):
        ctr[:32] = toByte(i, 32)
        offset = i * n
        outseeds[offset:offset+n] = prf(hashFunc, ctr, inseed, n)


def genChain(hashFunc: EHashFunction, inData, start, steps, params: WOTSParams, pubSeed, addr):
    out = [0] * params.n
    for j in range(params.n):
        out[j] = inData[j]
    for i in range(start, min(start + steps, params.w)):
        setHashAdrs(addr, i)
        out = hashF(hashFunc, out, pubSeed, addr, params.n)

    return out

def baseW(output, outLen, inputData, params):
    in_ = 0
    out = 0
    total = 0
    bits = 0
    consumed = 0
    while consumed < outLen:
        if bits == 0:
            total = inputData[in_]
            in_ += 1
            bits += 8
        bits -= params.logW
        output[out] = (total >> bits) & (params.w - 1)
        out += 1
        consumed += 1


def wotsPKGen(hashFunc: EHashFunction, pk, sk, params, pubSeed, addr):
    expandSeed(hashFunc, pk, sk, params.n, params.len)
    for i in range(params.len):
        setChainAdrs(addr, i)
        offset = i * params.n
        pk[offset:offset + params.n] = genChain(hashFunc, pk[offset:offset + params.n], 0, params.w - 1, params, pubSeed, addr)


def wotsSign(hashFunc: EHashFunction, msg, sk, params, pubSeed, addr):
    sig = [0] * params.len * params.n
    basew = [0] * params.len
    csum = 0

    baseW(basew, params.len1, msg, params)

    for i in range(params.len1):
        csum += params.w - 1 - basew[i]

    csum = csum << (8 - ((params.len2 * params.logW) % 8))

    len_2_bytes = ((params.len2 * params.logW) + 7) // 8
    csum_bytes = [0] * len_2_bytes
    csum_bytes[:len_2_bytes] = toByte(csum, len_2_bytes)

    csum_basew = [0] * params.len2
    baseW(csum_basew, params.len2, csum_bytes, params)

    for i in range(params.len2):
        basew[params.len1 + i] = csum_basew[i]

    expandSeed(hashFunc, sig, sk, params.n, params.len)

    for i in range(params.len):
        setChainAdrs(addr, i)
        offset = i * params.n
        sig[offset:offset + params.n] = genChain(hashFunc, sig[offset:offset + params.n], 0, basew[i], params, pubSeed,
                                                 addr)

    return sig


def wotsPKFromSig(hashFunc, pk, sig, msg, wotsParams, pubSeed, addr):
    xmssWotsLen = wotsParams.len
    xmssWotsLen1 = wotsParams.len1
    xmssWotsLen2 = wotsParams.len2
    xmssWotsLogW = wotsParams.logW
    xmssWotsW = wotsParams.w
    xmssN = wotsParams.n

    baseWVal = [0] * xmssWotsLen
    csum = 0
    csumBytes = bytearray(((xmssWotsLen2 * xmssWotsLogW) + 7) // 8)
    csumBaseW = [0] * xmssWotsLen2

    baseW(baseWVal, xmssWotsLen1, msg, wotsParams)

    for i in range(xmssWotsLen1):
        csum += xmssWotsW - 1 - baseWVal[i]

    csum = csum << (8 - ((xmssWotsLen2 * xmssWotsLogW) % 8))

    upto = ((xmssWotsLen2 * xmssWotsLogW) + 7) // 8
    csumBytes[:upto] = toByte(csum, upto)
    baseW(csumBaseW, xmssWotsLen2, csumBytes, wotsParams)

    for i in range(xmssWotsLen2):
        baseWVal[xmssWotsLen1 + i] = csumBaseW[i]
    for i in range(xmssWotsLen):
        setChainAdrs(addr, i)
        offset = i * xmssN
        pk[offset:offset + xmssN] = genChain(hashFunc, sig[offset:offset + xmssN], baseWVal[i], xmssWotsW - 1 - baseWVal[i],
                                         wotsParams, pubSeed, addr)
