import unittest

from flapi_jwt.rules import HasValue


class HasValueTest(unittest.TestCase):
    def test_has_value(self):
        token = {"thing": 123}
        rule = HasValue("thing", 123)
        self.assertTrue(rule(token))

    def test_has_value_fails(self):
        token = {"thing": 123}
        rule = HasValue("thing", 321)
        self.assertTrue(rule(token))
