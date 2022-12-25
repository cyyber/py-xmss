# py-xmss

Using extended seed
```
from xmss.xmssFast import XMSSFast

msg = b'This is a test message'

seed = "01040095cf61c788f37016930a3650e0124d6da1a6411b0183bf0abc739e39987bc33dcbbbf6e484bf5d7635f265627311da4a"

x = XMSSFast.fromExtendedSeed(bytearray.fromhex(seed))
x.setIndex(4)
signature = x.sign(msg)
isValid = XMSSFast.verify(msg, signature, x.getPK())

print(isValid)
print(x.getQAddress())
```

Using seed
```
from xmss.eHashFunctions import EHashFunction
from xmss.qrlAddressFormat import EAddrFormatType
from xmss.xmssFast import XMSSFast

msg = b'This is a test message'

seed = "95cf61c788f37016930a3650e0124d6da1a6411b0183bf0abc739e39987bc33dcbbbf6e484bf5d7635f265627311da4a"

x = XMSSFast(bytearray.fromhex(seed), 8, EHashFunction.SHAKE_128, EAddrFormatType.SHA256_2X)
x.setIndex(4)
signature = x.sign(msg)
isValid = XMSSFast.verify(msg, signature, x.getPK())

print(isValid)
print(x.getQAddress())
```