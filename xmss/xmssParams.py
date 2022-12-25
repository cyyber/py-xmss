from xmss.wotsParams import WOTSParams, wotsSetParams


class XMSSParams:
    def __init__(self):
        self.wotsPar = WOTSParams()
        self.n = 0
        self.h = 0
        self.k = 0


def xmssSetParams(params, n, h, w, k):
    if k >= h or k < 2 or (h - k) % 2:
        print("For BDS traversal, H - K must be even, with H > K >= 2!", file=sys.stderr)
        return

    params.h = h
    params.n = n
    params.k = k

    wotsPar = WOTSParams()
    wotsSetParams(wotsPar, n, w)
    params.wotsPar = wotsPar
