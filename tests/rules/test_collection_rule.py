import unittest

from flapi_jwt.rules import _CollectionRule


class CollectionRuleTest(unittest.TestCase):
    def test_fails(self):
        rule = _CollectionRule()
        self.assertRaises(NotImplementedError, rule, "token")
