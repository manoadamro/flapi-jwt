from . import app as _app, protect as _route, rules as _rules, errors as _errors

FlaskJwt = _app.FlaskJwt
current_token = FlaskJwt.current_token
current_handler = FlaskJwt.current_handler

protect = _route.Protect

JWTRule = _rules.JwtRule
HasScopes = _rules.HasScopes
MatchValue = _rules.MatchValue
HasKeys = _rules.HasKeys
HasValue = _rules.HasValue

AllOf = _rules.AllOf
AnyOf = _rules.AnyOf
NoneOf = _rules.NoneOf

JWTEncodeError = _errors.JWTEncodeError
JWTDecodeError = _errors.JWTDecodeError
JWTValidationError = _errors.JWTValidationError
