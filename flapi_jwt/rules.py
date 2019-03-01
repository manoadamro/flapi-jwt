from typing import Any, Callable, Dict, List

import flask
import jsonpointer


class JwtRule:
    def __call__(self, token: Dict) -> bool:
        raise NotImplementedError


class _CollectionRule(JwtRule):
    def __init__(self, *rules: JwtRule):
        self.rules = rules

    def __call__(self, item: Dict) -> bool:
        raise NotImplementedError


class AnyOf(_CollectionRule):
    def __call__(self, item: Dict) -> bool:
        return any(rule(item) for rule in self.rules)


class AllOf(_CollectionRule):
    def __call__(self, item: Dict) -> bool:
        return all(rule(item) for rule in self.rules)


class NoneOf(_CollectionRule):
    def __call__(self, item: Dict) -> bool:
        return not any(rule(item) for rule in self.rules)


class Callback(AllOf):
    def __init__(self, *funcs: Callable):
        super(Callback, self).__init__(*funcs)


class HasScopes(JwtRule):
    def __init__(self, *scopes: str):
        self.scopes = scopes

    def __call__(self, token: Dict) -> bool:
        jwt_scopes: List[str] = token.get("scp", [])
        return all(scope in jwt_scopes for scope in self.scopes)


class HasKeys(JwtRule):
    def __init__(self, *keys: str):
        self.keys = keys

    def __call__(self, token: Dict) -> bool:
        return all(key in token for key in self.keys)


class HasValue(JwtRule):
    def __init__(self, pointer: str, value):
        if not pointer.startswith("/"):
            pointer = f"/{pointer}"
        self.pointer = pointer
        self.value = value

    def __call__(self, token: Dict) -> bool:
        try:
            jsonpointer.resolve_pointer(token, self.pointer)
            return True
        except jsonpointer.JsonPointerException:
            return False

class MatchValue(JwtRule):
    def __init__(self, *paths):
        self.matchers: List[(Callable, str)] = [
            self._resolve_path(path) for path in paths
        ]
        if len(self.matchers) < 2:
            raise ValueError(f"MatchValue requires two or more paths")

    def __call__(self, token: Dict) -> bool:
        try:
            return self._check_equal(
                [matcher[0](matcher[1], token) for matcher in self.matchers]
            )
        except jsonpointer.JsonPointerException:
            return False
          
    def _resolve_path(self, path: str) -> (Callable, str):
        object_name, pointer = path.split(":")
        if not pointer.startswith("/"):
            pointer = f"/{pointer}"
        if object_name.startswith("_") or not hasattr(self, object_name):
            raise AttributeError(f"invalid match object {object_name}")
        obj: Callable = getattr(self, object_name)
        return obj, pointer

    @staticmethod
    def _check_equal(values: List[Any]) -> bool:
        return all(str(values[0]) == str(rest) for rest in values[1:])

    @staticmethod
    def header(path: str, _: Any) -> Any:
        return jsonpointer.resolve_pointer(flask.request.headers, path)

    @staticmethod
    def json(path: str, _: Any) -> Any:
        return jsonpointer.resolve_pointer(flask.request.json, path)

    @staticmethod
    def url(path: str, _: Any) -> Any:
        return jsonpointer.resolve_pointer(flask.request.view_args, path)

    @staticmethod
    def param(path: str, _: Any) -> Any:
        return jsonpointer.resolve_pointer(flask.request.args, path)

    @staticmethod
    def form(path: str, _: Any) -> Any:
        return jsonpointer.resolve_pointer(flask.request.form, path)

    @staticmethod
    def jwt(path: str, token: Dict) -> Any:
        return jsonpointer.resolve_pointer(token, path)
