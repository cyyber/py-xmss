from enum import Enum


class EHashFunction(Enum):
    SHA2_256 = 0
    SHAKE_128 = 1
    SHAKE_256 = 2
