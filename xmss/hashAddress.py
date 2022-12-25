def setType(adrs: list[int], addrType: int):
    adrs[3] = addrType
    for i in range(4, 8):
        adrs[i] = 0


def setKeyAndMask(adrs: list[int], keyAndMask: int):
    adrs[7] = keyAndMask


# OTS
def setOTSAdrs(adrs: list[int], ots: int):
    adrs[4] = ots


def setChainAdrs(adrs: list[int], chain: int):
    adrs[5] = chain


def setHashAdrs(adrs: list[int], hash: int):
    adrs[6] = hash


# L-tree
def setLTreeAdrs(adrs: list[int], ltree: int):
    adrs[4] = ltree


# Hash Tree & L-tree
def setTreeHeight(adrs: list[int], treeHeight: int):
    adrs[5] = treeHeight


def setTreeIndex(adrs: list[int], treeIndex: int):
    adrs[6] = treeIndex
