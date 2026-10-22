"""Unit tests for pmf_decode.py's decoders."""
import base64
import codecs
import os
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import pmf_decode


def test_decode_once_base64():
    payload = base64.b64encode(b"echo 1;")
    data = b"eval(base64_decode('" + payload + b"'));"
    new_data, changed = pmf_decode.decode_once(data)
    assert changed
    assert b"echo 1;" in new_data


def test_decode_once_str_rot13():
    rotated = codecs.encode("echo hi;", "rot_13")
    data = f"eval(str_rot13('{rotated}'));".encode()
    new_data, changed = pmf_decode.decode_once(data)
    assert changed
    assert b"echo hi;" in new_data


def test_decode_once_gzinflate():
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    payload = compressor.compress(b"echo deflated;") + compressor.flush()
    data = b"eval(gzinflate('" + payload + b"'));"
    new_data, changed = pmf_decode.decode_once(data)
    assert changed
    assert b"echo deflated;" in new_data


def test_decode_once_no_match_returns_unchanged():
    data = b"<?php echo 'just plain code'; ?>"
    new_data, changed = pmf_decode.decode_once(data)
    assert not changed
    assert new_data == data


def test_decode_once_invalid_payload_degrades_gracefully():
    data = b"eval(gzinflate('not valid compressed data'));"
    new_data, changed = pmf_decode.decode_once(data)
    assert not changed
    assert new_data == data


def test_recursive_decode_unwraps_nested_calls():
    inner = base64.b64encode(b"echo done;")
    rotated_once = codecs.encode(f"base64_decode('{inner.decode()}')", "rot_13")
    data = f"eval(str_rot13('{rotated_once}'));".encode()
    for _ in range(10):
        data, changed = pmf_decode.decode_once(data)
        if not changed:
            break
    assert b"echo done;" in data
