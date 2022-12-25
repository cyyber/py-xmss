from hashlib import sha256

from xmss.misc import ADDRESS_HASH_SIZE
from xmss.qrlAddressFormat import EAddrFormatType
from xmss.qrlDescriptor import QRLDescriptor


class QRLHelper:
    def __init__(self):
        pass

    @staticmethod
    def getAddress(extended_pk: bytes) -> list[int]:
        descr = QRLDescriptor.fromExtendedPK(extended_pk)

        if descr.getAddrFormatType() != EAddrFormatType.SHA256_2X:
            raise ValueError("Address format type not supported")

        descr_bytes = descr.getBytes()
        address = descr_bytes

        hasher = sha256()
        hasher.update(extended_pk)
        hashed_key = hasher.digest()

        address += hashed_key

        hasher = sha256()
        hasher.update(address)
        hashed_key2 = hasher.digest()
        address += hashed_key2[-4:]

        return address

    @staticmethod
    def addressIsValid(address: bytes) -> bool:
        try:
            if len(address) != QRLDescriptor.getSize() + ADDRESS_HASH_SIZE + 4:
                return False

            descr = QRLDescriptor.fromBytes(address[:QRLDescriptor.getSize()])

            if descr.getAddrFormatType() != EAddrFormatType.SHA256_2X:
                return False

            hasher = sha256()
            hasher.update(address[:QRLDescriptor.getSize() + ADDRESS_HASH_SIZE])
            hashed_key2 = hasher.digest()

            return (
                address[35] == hashed_key2[28]
                and address[36] == hashed_key2[29]
                and address[37] == hashed_key2[30]
                and address[38] == hashed_key2[31]
            )
        except:
            return False
