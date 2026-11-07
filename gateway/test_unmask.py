"""S3-23: the fast unmask gives the RFC 6455 result at every length."""
import os
import unittest

from server import MAX_FRAME, unmask


class Unmask(unittest.TestCase):
    def test_matches_the_definition(self):
        mask = bytes((0x12, 0x00, 0xff, 0x80))
        for n in (0, 1, 2, 3, 4, 5, 14, 125, 126, MAX_FRAME):
            raw = os.urandom(n)
            self.assertEqual(unmask(raw, mask), bytes(v ^ mask[i % 4] for i, v in enumerate(raw)))

    def test_keeps_trailing_zero_bytes(self):
        self.assertEqual(unmask(b'\x12\x34\x56\x78\x12', bytes((0x12, 0x34, 0x56, 0x78))), bytes(5))


if __name__ == '__main__':
    unittest.main()
