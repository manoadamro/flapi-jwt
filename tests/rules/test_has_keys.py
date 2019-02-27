import unittest

from flapi_jwt.rules import HasKeys


class HasKeysTest(unittest.TestCase):
    def test_has_scopes(self):
        token = {"thing": 123, "other": True}
        rule = HasKeys("thing", "other")
        self.assertTrue(rule(token))

    def test_has_scopes_fails(self):
        token = {"thing": 123}
        rule = HasKeys("thing", "other")
        self.assertFalse(rule(token))
