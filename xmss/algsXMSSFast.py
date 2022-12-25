from hashlib import shake_256

from xmss.hash import addrToByte, prf, hashH, hMsg
from xmss.hashAddress import setType, setLTreeAdrs, setOTSAdrs, setChainAdrs, setHashAdrs, setKeyAndMask, setTreeIndex, \
    setTreeHeight
from xmss.misc import toByte
from xmss.wots import wotsPKGen, wotsSign
from xmss.wotsParams import WOTSParams
from xmss.xmssCommon import lTree
from xmss.xmssParams import XMSSParams


class TreeHashInst:
    def __init__(self):
        self.h = 0
        self.nextIdx = 0
        self.stackUsage = 0
        self.completed = 0
        self.node = None


class BDSState:
    def __init__(self, stack, stackOffset, stackLevels, auth, keep, treeHash, retain, nextLeaf):
        self.stack = stack
        self.stackOffset = stackOffset
        self.stackLevels = stackLevels
        self.auth = auth
        self.keep = keep
        self.treeHash = treeHash
        self.retain = retain
        self.nextLeaf = nextLeaf


def getSeed(hashFunc, skSeed, n, addr) -> bytes:
    byteData = [0] * 32

    # Make sure that chain addr, hash addr, and key bit are 0!
    setChainAdrs(addr, 0)
    setHashAdrs(addr, 0)
    setKeyAndMask(addr, 0)

    # Generate pseudorandom value
    addrToByte(byteData, addr)
    return prf(hashFunc, byteData, skSeed, n)


def xmssSetBDSState(state: BDSState, stack, stackOffset, stackLevels, auth, keep, treeHash, retain, nextLeaf):
    state.stack = stack
    state.stackOffset = stackOffset
    state.stackLevels = stackLevels
    state.auth = auth
    state.keep = keep
    state.treeHash = treeHash
    state.retain = retain
    state.nextLeaf = nextLeaf


def genLeafWOTS(hashFunc, skSeed, params, pubSeed, ltreeAddr, otsAddr):
    leaf = [0] * params.n
    pk = [0] * params.wotsPar.keySize
    seed = getSeed(hashFunc, skSeed, params.n, otsAddr)
    wotsPKGen(hashFunc, pk, seed, params.wotsPar, pubSeed, otsAddr)

    lTree(hashFunc, params.wotsPar, leaf, pk, pubSeed, ltreeAddr)
    return leaf


def treeHashMinHeightOnStack(state: BDSState, params, treehash: TreeHashInst):
    r = params.h
    for i in range(treehash.stackUsage):
        if state.stackLevels[state.stackOffset - i - 1] < r:
            r = state.stackLevels[state.stackOffset - i - 1]
    return r


def treeHashSetup(hashFunc, node, height, index, state: BDSState, skSeed, params, pubSeed, addr):
    idx = index
    n = params.n
    h = params.h
    k = params.k
    otsAddr = [0] * 8
    lTreeAddr = [0] * 8
    nodeAddr = [0] * 8

    otsAddr[:12] = addr[:12]
    setType(otsAddr, 0)

    lTreeAddr[:12] = addr[:12]
    setType(lTreeAddr, 1)

    nodeAddr[:12] = addr[:12]
    setType(nodeAddr, 2)

    stack = [0] * ((height + 1) * n)
    stackLevels = [0] * (height + 1)
    stackOffset = 0

    lastNode = idx + (1 << height)

    bound = h - k
    for i in range(bound):
        state.treeHash[i].h = i
        state.treeHash[i].completed = 1
        state.treeHash[i].stackUsage = 0

    i = 0
    for idx in range(idx, lastNode):
        setLTreeAdrs(lTreeAddr, idx)
        setOTSAdrs(otsAddr, idx)
        stack[stackOffset * n:stackOffset * n+n] = genLeafWOTS(hashFunc, skSeed, params, pubSeed, lTreeAddr, otsAddr)
        stackLevels[stackOffset] = 0
        stackOffset += 1
        if h - k > 0 and i == 3:
            state.treeHash[0].node = stack[stackOffset * n:stackOffset * n+n]
        while stackOffset > 1 and stackLevels[stackOffset - 1] == stackLevels[stackOffset - 2]:
            nodeH = stackLevels[stackOffset - 1]
            if i >> nodeH == 1:
                state.auth[nodeH * n:nodeH * n+n] = stack[(stackOffset - 1) * n:stackOffset * n]
            else:
                if nodeH < h - k and i >> nodeH == 3:
                    state.treeHash[nodeH].node = stack[(stackOffset - 1) * n:stackOffset * n]
                elif nodeH >= h - k:
                    retainOffset = ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >> nodeH) - 3) >> 1)) * n
                    state.retain[retainOffset:retainOffset + n] = stack[(stackOffset - 1) * n:stackOffset * n]
            setTreeHeight(nodeAddr, stackLevels[stackOffset - 1])
            setTreeIndex(nodeAddr, (idx >> (stackLevels[stackOffset - 1] + 1)))
            stack[(stackOffset - 2) * n:(stackOffset - 1) * n] = hashH(hashFunc, stack[(stackOffset - 2) * n:stackOffset * n],
                                                                       pubSeed, nodeAddr, n)
            stackLevels[stackOffset - 2] += 1
            stackOffset -= 1
        i += 1

    node[:n] = stack[:n]


def treeHashUpdate(hashFunc, treeHash: TreeHashInst, state: BDSState, skSeed, params, pubSeed, addr):
    n = params.n

    otsAddr = [0] * 8
    lTreeAddr = [0] * 8
    nodeAddr = [0] * 8
    # only copy layer and tree address parts
    otsAddr[:3] = addr[:3]
    # type = ots
    setType(otsAddr, 0)
    lTreeAddr[:3] = addr[:3]
    setType(lTreeAddr, 1)
    nodeAddr[:3] = addr[:3]
    setType(nodeAddr, 2)

    setLTreeAdrs(lTreeAddr, treeHash.nextIdx)
    setOTSAdrs(otsAddr, treeHash.nextIdx)

    nodeBuffer = [0] * (2 * n)
    nodeHeight = 0
    nodeBuffer[:n] = genLeafWOTS(hashFunc, skSeed, params, pubSeed, lTreeAddr, otsAddr)
    while treeHash.stackUsage > 0 and state.stackLevels[state.stackOffset - 1] == nodeHeight:
        nodeBuffer[n:] = nodeBuffer[:n]
        nodeBuffer[:n] = state.stack[(state.stackOffset - 1) * n:(state.stackOffset - 1) * n + n]
        setTreeHeight(nodeAddr, nodeHeight)
        setTreeIndex(nodeAddr, treeHash.nextIdx >> (nodeHeight + 1))
        nodeBuffer[:n] = hashH(hashFunc, nodeBuffer, pubSeed, nodeAddr, n)
        nodeHeight += 1
        treeHash.stackUsage -= 1
        state.stackOffset -= 1
    if nodeHeight == treeHash.h:  # this also implies stackusage == 0
        treeHash.node = nodeBuffer[:n]
        treeHash.completed = True
    else:
        state.stack[state.stackOffset * n:(state.stackOffset + 1) * n] = nodeBuffer[:n]
        treeHash.stackUsage += 1
        state.stackLevels[state.stackOffset] = nodeHeight
        state.stackOffset += 1
        treeHash.nextIdx += 1


def bdsTreeHashUpdate(hashFunc, state: BDSState, updates, skSeed, params, pubSeed, addr):
    h = params.h
    k = params.k
    used = 0

    for j in range(updates):
        lMin = h
        level = h - k
        for i in range(h - k):
            if state.treeHash[i].completed:
                low = h
            elif state.treeHash[i].stackUsage == 0:
                low = i
            else:
                low = treeHashMinHeightOnStack(state, params, state.treeHash[i])
            if low < lMin:
                level = i
                lMin = low
        if level == h - k:
            break
        treeHashUpdate(hashFunc, state.treeHash[level], state, skSeed, params, pubSeed, addr)
        used += 1

    return updates - used

def bdsRound(hashFunc, state: BDSState, leafIdx, skSeed, params, pubSeed, addr):
    n = params.n
    h = params.h
    k = params.k

    tau = h
    buf = [0] * (2 * n)

    otsAddr = addr[:8]
    ltreeAddr = addr[:8]
    nodeAddr = addr[:8]
    # only copy layer and tree address parts
    otsAddr[:12] = addr[:12]
    # type = ots
    setType(otsAddr, 0)
    ltreeAddr[:12] = addr[:12]
    setType(ltreeAddr, 1)
    nodeAddr[:12] = addr[:12]
    setType(nodeAddr, 2)

    for i in range(h):
        if not ((leafIdx >> i) & 1):
            tau = i
            break

    if tau > 0:
        buf[:n] = state.auth[(tau - 1) * n:tau * n]
        # we need to do this before refreshing state.keep to prevent overwriting
        buf[n:2 * n] = state.keep[((tau - 1) >> 1) * n:((tau - 1) >> 1) * n + n]
    if not ((leafIdx >> (tau + 1)) & 1) and (tau < h - 1):
        state.keep[(tau >> 1) * n:(tau >> 1) * n + n] = state.auth[tau * n:(tau + 1) * n]
    if tau == 0:
        setLTreeAdrs(ltreeAddr, leafIdx)
        setOTSAdrs(otsAddr, leafIdx)
        state.auth[:n] = genLeafWOTS(hashFunc, skSeed, params, pubSeed, ltreeAddr, otsAddr)
    else:
        setTreeHeight(nodeAddr, (tau - 1))
        setTreeIndex(nodeAddr, leafIdx >> tau)
        state.auth[tau * n:(tau + 1) * n] = hashH(hashFunc, buf, pubSeed, nodeAddr, n)
        for i in range(tau):
            if i < h - k:
                state.auth[i * n:(i + 1) * n] = state.treeHash[i].node
            else:
                offset = (1 << (h - 1 - i)) + i - h
                rowIdx = ((leafIdx >> i) - 1) >> 1
                state.auth[i * n:(i + 1) * n] = state.retain[(offset + rowIdx) * n:(offset + rowIdx + 1) * n]

        for i in range((tau if tau < h - k else (h - k))):
            startIdx = leafIdx + 1 + 3 * (1 << i)
            if startIdx < 1 << h:
                state.treeHash[i].h = i
                state.treeHash[i].nextIdx = startIdx
                state.treeHash[i].completed = 0
                state.treeHash[i].stackUsage = 0


def xmssFastGenKeyPair(hashFunc, params, pk, sk, state: BDSState, seed):
    if params.h & 1:
        print("Not a valid h, only even numbers supported! Try again with an even number")
        return -1
    n = params.n

    # Set idx = 0
    sk[0] = 0
    sk[1] = 0
    sk[2] = 0
    sk[3] = 0

    # Copy PUB_SEED to public key
    hasher = shake_256()
    hasher.update(seed)
    randomBits = hasher.digest(3 * n)

    rnd = 96
    pks = 32
    sk[4:4+rnd] = randomBits[:rnd]
    pk[n:n+pks] = sk[4+2*n:4+2*n+pks]

    addr = [0, 0, 0, 0, 0, 0, 0, 0]

    # Compute root
    treeHashSetup(hashFunc, pk, params.h, 0, state, sk[4:4+2*n], params, sk[4+2*n:4+3*n], addr)
    # copy root to sk
    sk[4+3*n:4+3*n+pks] = pk[:pks]
    return 0


def xmssFastUpdate(hashFunc, params, sk, state: BDSState, newIdx):
    numElems = (1 << params.h)

    currentIdx = ((sk[0] << 24) | (sk[1] << 16) | (sk[2] << 8) | sk[3])

    # Verify ranges
    if newIdx >= numElems:
        raise ValueError("index too high")

    if newIdx < currentIdx:
        raise ValueError("cannot rewind")

    # Change index
    skSeed = sk[4:36]
    pubSeed = sk[68:100]

    otsAddr = [0, 0, 0, 0, 0, 0, 0, 0]

    for j in range(currentIdx, newIdx):
        if j >= numElems:
            return -1

        bdsRound(hashFunc, state, j, skSeed, params, pubSeed, otsAddr)
        bdsTreeHashUpdate(hashFunc, state, (params.h - params.k) >> 1, skSeed, params, pubSeed, otsAddr)

    # update secret key index
    sk[0] = (newIdx >> 24) & 255
    sk[1] = (newIdx >> 16) & 255
    sk[2] = (newIdx >> 8) & 255
    sk[3] = newIdx & 255

    return 0


def xmssFastSignMsg(hashFunc, params: XMSSParams, sk, state: BDSState, sigMsg, msg, msgLen):
    n = params.n

    # Extract SK
    idx = (sk[0] << 24) | (sk[1] << 16) | (sk[2] << 8) | sk[3]
    skSeed = sk[4: 4 + n]
    skPrf = sk[4 + n: 4 + 2 * n]
    pubSeed = sk[4 + 2 * n: 4 + 3 * n]

    # index as 32 bytes string
    idxBytes32 = [0] * 32
    idxBytes32[:32] = toByte(idx, 32)

    hashKey = [None] * (3 * n)

    # Update SK
    sk[0] = ((idx + 1) >> 24) & 255
    sk[1] = ((idx + 1) >> 16) & 255
    sk[2] = ((idx + 1) >> 8) & 255
    sk[3] = (idx + 1) & 255
    # -- Secret key for this non-forward-secure version is now updated.
    # -- A productive implementation should use a file handle instead and write the updated secret key at this point!

    # Init working params
    msgH = [None] * n
    R = [None] * n
    otsAddr = [0, 0, 0, 0, 0, 0, 0, 0]

    # ---------------------------------
    # Message Hashing
    # ---------------------------------

    # Message Hash:
    # First compute pseudorandom value
    R[:n] = prf(hashFunc, idxBytes32, skPrf, n)
    # Generate hash key (R || root || idx)
    hashKey[:n] = R
    hashKey[n: 2 * n] = sk[4 + 3 * n: 4 + 4 * n]
    hashKey[2 * n:2 * n+n] = toByte(idx, n)
    # Then use it for message digest
    msgH[:n] = hMsg(hashFunc, msg, msgLen, hashKey, 3 * n, n)

    # Start collecting signature
    sigMsgLen = 0

    # Copy index to signature
    sigMsg[0] = (idx >> 24) & 255
    sigMsg[1] = (idx >> 16) & 255
    sigMsg[2] = (idx >> 8) & 255
    sigMsg[3] = idx & 255

    sigMsgLen += 4

    # Copy R to signature
    for i in range(n):
        sigMsg[sigMsgLen+i] = R[i]

    sigMsgLen += n

    # ----------------------------------
    # Now we start to "really sign"
    # ----------------------------------

    # Prepare Address
    setType(otsAddr, 0)
    setOTSAdrs(otsAddr, idx)

    # Compute seed for OTS key pair
    otsSeed = getSeed(hashFunc, skSeed, n, otsAddr)

    # Compute WOTS signature
    sigMsg[sigMsgLen:sigMsgLen+params.wotsPar.keySize] = wotsSign(hashFunc, msgH, otsSeed, params.wotsPar, pubSeed, otsAddr)

    sigMsgLen += params.wotsPar.keySize

    # the auth path was already computed during the previous round
    sigMsg[sigMsgLen:sigMsgLen + params.h * params.n] = state.auth[:params.h * params.n]

    if idx < (1 << params.h) - 1:
        bdsRound(hashFunc, state, idx, skSeed, params, pubSeed, otsAddr)
        bdsTreeHashUpdate(hashFunc, state, (params.h - params.k) >> 1, skSeed, params, pubSeed, otsAddr)

    return 0
