from os import SEEK_END
from typing import BinaryIO


def get_fsize(f: BinaryIO) -> int:
    """Get the size of a file-like object"""
    current_pos = f.tell()
    f.seek(0, SEEK_END)
    f_size = f.tell()
    f.seek(current_pos)
    return f_size
