import math


class WOTSParams:
    def __init__(self):
        self.len1 = 0
        self.len2 = 0
        self.len = 0
        self.n = 0
        self.w = 0
        self.logW = 0
        self.keySize = 0


def wotsSetParams(params, n, w):
    params.n = n
    params.w = w
    params.logW = int(math.log2(w))
    params.len1 = int(math.ceil((8 * n) / params.logW))
    params.len2 = int(math.floor(math.log2(params.len1 * (w - 1)) / params.logW) + 1)
    params.len = params.len1 + params.len2
    params.keySize = params.len * params.n
