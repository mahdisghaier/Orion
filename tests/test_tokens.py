"""Login tokens: what a valid, expired, forged or tampered token does.

Run:  python -m unittest discover -s tests -t . -v
"""
import time
import unittest

import jwt

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, decode_token


class Tokens(unittest.TestCase):
    def test_a_fresh_access_token_decodes_to_its_claims(self):
        claims = decode_token(create_access_token("user-1", "soc_l2"))
        self.assertEqual((claims["sub"], claims["role"], claims["type"]), ("user-1", "soc_l2", "access"))

    def test_refresh_and_access_tokens_are_told_apart(self):
        self.assertEqual(decode_token(create_refresh_token("u", "admin"))["type"], "refresh")

    def test_an_expired_token_is_refused(self):
        expired = jwt.encode({"sub": "u", "role": "admin", "type": "access", "exp": int(time.time()) - 5},
                             settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        self.assertIsNone(decode_token(expired))

    def test_a_token_signed_with_another_key_is_refused(self):
        forged = jwt.encode({"sub": "u", "role": "admin", "type": "access", "exp": int(time.time()) + 600},
                            "not-the-real-secret-key-0123456789abcdef", algorithm=settings.JWT_ALGORITHM)
        self.assertIsNone(decode_token(forged))

    def test_a_tampered_payload_is_refused(self):
        token = create_access_token("u", "soc_l1")
        head, payload, signature = token.split(".")
        other = jwt.encode({"sub": "u", "role": "admin", "type": "access", "exp": int(time.time()) + 600},
                           "x" * 40, algorithm=settings.JWT_ALGORITHM).split(".")[1]
        self.assertIsNone(decode_token(f"{head}.{other}.{signature}"))

    def test_the_none_algorithm_is_refused(self):
        unsigned = jwt.encode({"sub": "u", "role": "admin", "type": "access", "exp": int(time.time()) + 600}, None, algorithm="none")
        self.assertIsNone(decode_token(unsigned))

    def test_garbage_is_refused(self):
        for junk in ("", "abc", "a.b.c", "....", "é.中.x"):
            self.assertIsNone(decode_token(junk))


if __name__ == "__main__":
    unittest.main()
