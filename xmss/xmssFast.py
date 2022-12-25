import binascii

from xmss.algsXMSSFast import TreeHashInst, xmssFastGenKeyPair, xmssFastSignMsg, xmssFastUpdate, BDSState
from xmss.eHashFunctions import EHashFunction
from xmss.qrlAddressFormat import EAddrFormatType
from xmss.qrlDescriptor import QRLDescriptor, ESignatureType
from xmss.qrlHelper import QRLHelper
from xmss.wotsParams import WOTSParams, wotsSetParams
from xmss.xmssCommon import xmssVerifySig
from xmss.xmssParams import XMSSParams, xmssSetParams


XMSS_MAX_HEIGHT = 254

OFFSET_IDX = 0
OFFSET_SK_SEED = OFFSET_IDX + 4
OFFSET_SK_PRF = OFFSET_SK_SEED + 32
OFFSET_PUB_SEED = OFFSET_SK_PRF + 32
OFFSET_ROOT = OFFSET_PUB_SEED + 32


class XMSSFast:
    def __init__(self, seed: bytes, height: int, hashFunction: EHashFunction, addrFormatType: EAddrFormatType):
        self._state = None
        self._stackOffset = 0
        self._stack = []
        self._stackLevels = []
        self._auth = []
        self._keep = []
        self._treeHash = []
        self._thNodes = []
        self._retain = []

        self.params = XMSSParams()
        self._hashFunction = hashFunction
        self._addrFormatType = addrFormatType
        self._height = height
        self._sk = None
        self._seed = seed
        self.initializeTree()

    @staticmethod
    def fromExtendedSeed(extendedSeed):
        if len(extendedSeed) != 51:
            raise Exception("Extended seed should be 51 bytes. Other values are not currently supported")

        desc = QRLDescriptor.fromExtendedSeed(extendedSeed)

        _seed = extendedSeed[QRLDescriptor.getSize():]
        _height = desc.getHeight()
        _hashFunction = desc.getHashFunction()
        _addrFormatType = desc.getAddrFormatType()
        return XMSSFast(_seed, _height, _hashFunction, _addrFormatType)

    def initializeTree(self, wotsParamW: int=16):
        self._sk = [0] * 132
        tmp = [0] * 64

        k = 2
        w = wotsParamW
        n = 32

        if k >= self._height or (self._height - k) % 2:
            raise ValueError("For BDS traversal, H - K must be even, with H > K >= 2!")

        xmssSetParams(self.params, n, self._height, w, k)

        self._stackOffset = 0
        self._stack = [0] * ((self._height + 1) * n)
        self._stackLevels = [0] * (self._height + 1)
        self._auth = [0] * (self._height * n)
        self._keep = [0] * ((self._height >> 1) * n)
        self._thNodes = [0] * ((self._height - k) * n)
        self._retain = [0] * (((1 << k) - k - 1) * n)

        for i in range(self._height - k):
            self._treeHash.append(TreeHashInst())
            self._treeHash[i].node = self._thNodes[n * i]

        self._state = BDSState(self._stack,
                               self._stackOffset,
                               self._stackLevels,
                               self._auth,
                               self._keep,
                               self._treeHash,
                               self._retain,
                               0)

        xmssFastGenKeyPair(self._hashFunction,
                           self.params,
                           tmp,
                           self._sk,
                           self._state,
                           self._seed)

    def setIndex(self, newIndex: int):
        xmssFastUpdate(self._hashFunction,
                       self.params,
                       self._sk,
                       self._state,
                       newIndex)

        return newIndex

    def sign(self, message):
        signature = [0] * self.getSignatureSize(self.params.wotsPar.w)

        index = self.getIndex()
        self.setIndex(index)

        xmssFastSignMsg(self._hashFunction,
                        self.params,
                        self._sk,
                        self._state,
                        signature,
                        message,
                        len(message))

        return signature

    @staticmethod
    def verify(message, signature, extendedPK, wotsParamW=16):
        try:
            if len(extendedPK) != 67:
                raise ValueError("Invalid extended_pk size. It should be 67 bytes")
            signatureBaseSize = XMSSFast.calculateSignatureBaseSize(wotsParamW)
            if len(signature) > signatureBaseSize + 254 * 32:
                raise ValueError("invalid signature size. Height<=254")

            desc = QRLDescriptor.fromExtendedPK(extendedPK)

            if desc.getSignatureType() != ESignatureType.XMSS:
                return False

            height = XMSSFast.getHeightFromSigSize(len(signature), wotsParamW)

            if height == 0 or desc.getHeight() != height:
                return False

            hashFunction = desc.getHashFunction()

            params = XMSSParams()
            k = 2
            w = wotsParamW
            n = 32

            if k >= height or (height - k) % 2:
                raise ValueError("For BDS traversal, H - K must be even, with H > K >= 2!")

            xmssSetParams(params, n, height, w, k)

            tmp = signature

            return xmssVerifySig(hashFunction, params.wotsPar, message, len(message), tmp,
                                 extendedPK[QRLDescriptor.getSize():], height) == 0
        except ValueError:
            return False

    def getSK(self) -> bytes:
        return bytes(self._sk)

    def getPK(self) -> bytes:
        pk = self.getDescriptorBytes()
        root = self.getRoot()
        pubSeed = self.getPKSeed()
        pk += bytes(root)
        pk += bytes(pubSeed)

        return pk

    def getDescriptor(self):
        return QRLDescriptor(self._hashFunction, ESignatureType.XMSS, self._height, self._addrFormatType)

    def getDescriptorBytes(self) -> bytes:
        return self.getDescriptor().getBytes()

    def getHeight(self):
        return self._height

    def getSeed(self):
        return self._seed

    def getExtendedSeed(self):
        extendedSeed = self.getDescriptorBytes()
        extendedSeed += self._seed
        return extendedSeed

    def getRoot(self):
        return self._sk[OFFSET_ROOT:OFFSET_ROOT + 32]

    def getPKSeed(self):
        return self._sk[OFFSET_PUB_SEED:OFFSET_PUB_SEED + 32]

    def getAddress(self):
        return QRLHelper.getAddress(self.getPK())

    def getQAddress(self):
        return 'Q' + binascii.hexlify(QRLHelper.getAddress(self.getPK())).decode()

    def getNumberSignatures(self):
        return 1 << self._height

    def getRemainingSignatures(self):
        return self.getNumberSignatures() - self.getIndex()

    def getIndex(self):
        return (self._sk[0] << 24) + (self._sk[1] << 16) + (self._sk[2] << 8) + self._sk[3]

    def getSignatureSize(self, wotsParamW=16):
        signatureBaseSize = self.calculateSignatureBaseSize(wotsParamW)
        return signatureBaseSize + self._height * 32

    @staticmethod
    def calculateSignatureBaseSize(wotsParamW=16):
        wotsParams = WOTSParams()
        wotsSetParams(wotsParams, 32, wotsParamW)
        return 4 + 32 + wotsParams.keySize

    @staticmethod
    def getHeightFromSigSize(sigSize, wotsParamW=16):
        signatureBaseSize = XMSSFast.calculateSignatureBaseSize(wotsParamW)
        if sigSize < signatureBaseSize:
            raise ValueError("Invalid signature size")
        if (sigSize - 4) % 32 != 0:
            raise ValueError("Invalid signature size")
        height = (sigSize - signatureBaseSize) / 32
        return int(height)

    def getSecretKeySize(self):
        return 132

    def getPublicKeySize(self):
        return QRLDescriptor.getSize() + 64
