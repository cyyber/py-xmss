from enum import Enum

from xmss.eHashFunctions import EHashFunction
from xmss.qrlAddressFormat import EAddrFormatType


class ESignatureType(Enum):
    XMSS = 0


class QRLDescriptor:
    def __init__(self, hashFunction: EHashFunction, signatureType: ESignatureType, height, addrFormatType: EAddrFormatType):
        self._hashFunction = hashFunction
        self._signatureType = signatureType
        self._height = height
        self._addrFormatType = addrFormatType

    def getHashFunction(self):
        return self._hashFunction

    def getSignatureType(self) -> ESignatureType:
        return self._signatureType

    def getHeight(self):
        return self._height

    def getAddrFormatType(self):
        return self._addrFormatType

    @staticmethod
    def fromExtendedSeed(extendedSeed):
        if len(extendedSeed) != 51:
            raise ValueError("Extended seed should be 51 bytes")

        return QRLDescriptor.fromBytes(extendedSeed[:QRLDescriptor.getSize()])

    @staticmethod
    def fromExtendedPK(extendedPK: bytes):
        if len(extendedPK) != 67:
            raise ValueError("Invalid extended_pk size. It should be 67 bytes")

        return QRLDescriptor.fromBytes(extendedPK[:QRLDescriptor.getSize()])

    @staticmethod
    def fromBytes(bytesData: bytes):
        if len(bytesData) != 3:
            raise ValueError("Descriptor size should be 3 bytes")

        hashFunction = EHashFunction(bytesData[0] & 0x0F)
        signatureType = ESignatureType((bytesData[0] >> 4) & 0xF0)
        height = (bytesData[1] & 0x0F) << 1
        addrFormatType = EAddrFormatType((bytesData[1] & 0xF0) >> 4)

        return QRLDescriptor(hashFunction, signatureType, height, addrFormatType)

    @staticmethod
    def getSize():
        return 3

    def getBytes(self) -> bytes:
        descr = [
            (self._signatureType.value << 4) | (self._hashFunction.value & 0x0F),
            (self._addrFormatType.value << 4) | ((self._height >> 1) & 0x0F),
            0
        ]
        return bytes(descr)
