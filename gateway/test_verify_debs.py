import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify_debs', here/'verify-debs.py')
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


class Debs(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root/'a.deb').write_bytes(b'a')
        self.pins = self.root/'pins.json'
        self.pins.write_text(json.dumps({'privateUbuntuNoblePackages': [
            {'file': 'a.deb', 'sha256': hashlib.sha256(b'a').hexdigest()}]}))

    def test_exact_set_passes(self):
        self.assertEqual(V.check(self.pins, self.root), [])

    def test_changed_missing_and_extra_are_refused(self):
        (self.root/'a.deb').write_bytes(b'b')
        self.assertEqual(V.check(self.pins, self.root), ['sha256 differs a.deb'])
        (self.root/'a.deb').unlink()
        self.assertEqual(V.check(self.pins, self.root), ['missing a.deb'])
        (self.root/'a.deb').write_bytes(b'a')
        (self.root/'x.deb').write_bytes(b'x')
        self.assertEqual(V.check(self.pins, self.root), ['not pinned x.deb'])

    def test_the_real_pin_file_is_readable(self):
        self.assertTrue(V.check(here/'dependencies.json', self.root))


if __name__ == '__main__':
    unittest.main()
