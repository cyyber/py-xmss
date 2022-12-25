ADDRESS_HASH_SIZE = 32


def toByte(inputData: int, byteData) -> list:
    out = [0] * byteData
    for i in range(byteData - 1, -1, -1):
        out[i] = inputData & 0xff
        inputData = inputData >> 8

    return out
