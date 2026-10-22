#!/usr/bin/env python3
"""cxs's --decode [file]: recursively decode PHP base64/rot13/gzinflate/
gzuncompress calls with a literal string argument, and print the result.
Not foolproof (only handles a literal quoted string as the argument, not
nested expressions) - same caveat cxs documents for its own --decode."""
import sys
import re
import base64
import codecs
import zlib

CALL_RE = re.compile(
    rb"(base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode)\s*\(\s*['\"](.*?)['\"]\s*\)",
    re.DOTALL,
)

DECODERS = {
    b"base64_decode": lambda s: base64.b64decode(s + b"=" * (-len(s) % 4), validate=False),
    b"str_rot13": lambda s: codecs.encode(s.decode("latin1"), "rot_13").encode("latin1"),
    b"gzinflate": lambda s: zlib.decompress(s, -15),
    b"gzuncompress": zlib.decompress,
    b"gzdecode": lambda s: zlib.decompress(s, 16 + zlib.MAX_WBITS),
}


def decode_once(data):
    """Replaces the first decodable call found with its decoded result.
    Returns (new_data, changed)."""
    m = CALL_RE.search(data)
    if not m:
        return data, False
    func, arg = m.group(1), m.group(2)
    try:
        decoded = DECODERS[func](arg)
    except Exception:
        return data, False
    return data[:m.start()] + decoded + data[m.end():], True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file> [max_depth]", file=sys.stderr)
        sys.exit(1)
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    for depth in range(max_depth):
        data, changed = decode_once(data)
        if not changed:
            break
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
