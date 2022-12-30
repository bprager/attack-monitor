from enum import Enum


class Mode(Enum):
    TIME = 0  # Display latest
    FREQ = 1  # Display most frequent
    NUM = 2  # Display most active
