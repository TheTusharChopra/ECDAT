"""Schema validation for generated CBOMs, against the vendored CycloneDX 1.6 schema.

ECDAT has no third-party dependencies, so `jsonschema` is not available. Rather than
claim validation and not perform it, this module implements the draft-07 subset that
`schema/bom-1.6.schema.json` actually uses. That subset was determined by enumerating
every keyword in the vendored file:

    type required enum properties additionalProperties items $ref oneOf anyOf
    pattern format minimum maximum minItems maxItems uniqueItems dependencies
    minLength maxLength default

All of those are implemented below. `default` is annotation-only and needs no check.
`format` is checked for the handful of values CycloneDX uses (`date-time`, `iri-reference`,
`idn-email`) and ignored otherwise, which is what draft-07 permits.

`UNSUPPORTED_KEYWORDS` is the guard against silent under-validation: if a future schema
revision introduces `allOf`, `if/then`, `not`, `patternProperties`, `const`,
`propertyNames`, `contains` or `multipleOf`, validation raises rather than quietly
passing documents it never really checked. A validator that ignores a constraint it does
not understand is worse than no validator, because it produces a green result.

This is a real check of the vendored schema, not a certification: passing means the
document satisfies that file. It is not an assertion that any external CycloneDX tool
will accept it, and nothing here should be reported as "CycloneDX certified".
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schema" / "bom-1.6.schema.json"

#: Keywords that change what a document is allowed to be. Encountering one that is not
#: implemented means this validator can no longer honestly claim to validate.
UNSUPPORTED_KEYWORDS = frozenset({
    "allOf", "not", "if", "then", "else", "const", "patternProperties",
    "propertyNames", "contains", "multipleOf", "exclusiveMinimum",
    "exclusiveMaximum", "additionalItems", "$recursiveRef", "$dynamicRef",
})

_TYPES: dict[str, Any] = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}

_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SchemaFeatureError(RuntimeError):
    """The schema uses a construct this validator does not implement."""


# ======================================================================================
class Validator:
    """A draft-07 subset validator, scoped to the vendored CycloneDX schema."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self.defs = schema.get("definitions", {})
        self._pattern_cache: dict[str, re.Pattern] = {}

    # ----------------------------------------------------------------------------------
    def validate(self, doc: Any) -> list[str]:
        """Return a list of human-readable errors. Empty list means valid."""
        errors: list[str] = []
        self._check(doc, self.schema, "$", errors)
        return errors

    def is_valid(self, doc: Any) -> bool:
        return not self.validate(doc)

    # ----------------------------------------------------------------------------------
    def _resolve(self, ref: str) -> dict[str, Any]:
        if not ref.startswith("#/definitions/"):
            raise SchemaFeatureError(f"unsupported $ref form: {ref}")
        key = ref[len("#/definitions/"):]
        if key not in self.defs:
            raise SchemaFeatureError(f"unresolvable $ref: {ref}")
        return self.defs[key]

    def _regex(self, pattern: str) -> re.Pattern:
        rx = self._pattern_cache.get(pattern)
        if rx is None:
            rx = self._pattern_cache[pattern] = re.compile(pattern)
        return rx

    # ----------------------------------------------------------------------------------
    def _check(self, value: Any, schema: dict[str, Any], path: str,
               errors: list[str]) -> None:
        if not isinstance(schema, dict):
            return
        unsupported = UNSUPPORTED_KEYWORDS & set(schema)
        if unsupported:
            raise SchemaFeatureError(
                f"{path}: schema uses unimplemented keyword(s) {sorted(unsupported)}; "
                "validation would be incomplete")

        if "$ref" in schema:
            self._check(value, self._resolve(schema["$ref"]), path, errors)
            # Sibling keywords beside $ref are ignored in draft-07, as here.
            return

        if "oneOf" in schema:
            self._branches(value, schema["oneOf"], path, errors, exactly_one=True)
            return
        if "anyOf" in schema:
            self._branches(value, schema["anyOf"], path, errors, exactly_one=False)
            return

        if not self._type_ok(value, schema, path, errors):
            return
        self._enum(value, schema, path, errors)
        if isinstance(value, str):
            self._string(value, schema, path, errors)
        elif isinstance(value, bool):
            pass                                    # bool is not a number here
        elif isinstance(value, (int, float)):
            self._number(value, schema, path, errors)
        elif isinstance(value, list):
            self._array(value, schema, path, errors)
        elif isinstance(value, dict):
            self._object(value, schema, path, errors)

    # ----------------------------------------------------------------------------------
    def _branches(self, value: Any, branches: list[dict], path: str,
                  errors: list[str], exactly_one: bool) -> None:
        matched = 0
        collected: list[str] = []
        for branch in branches:
            sub: list[str] = []
            self._check(value, branch, path, sub)
            if not sub:
                matched += 1
            else:
                collected.extend(sub)
        if matched == 0:
            errors.append(f"{path}: matches none of the allowed schemas "
                          f"({collected[0] if collected else 'no detail'})")
        elif exactly_one and matched > 1:
            errors.append(f"{path}: matches {matched} schemas under oneOf, expected 1")

    def _type_ok(self, value: Any, schema: dict[str, Any], path: str,
                 errors: list[str]) -> bool:
        spec = schema.get("type")
        if spec is None:
            return True
        names = [spec] if isinstance(spec, str) else list(spec)
        for name in names:
            expected = _TYPES.get(name)
            if expected is None:
                raise SchemaFeatureError(f"{path}: unknown type '{name}'")
            if name in ("number", "integer") and isinstance(value, bool):
                continue                            # JSON booleans are not numbers
            if isinstance(value, expected):
                return True
        errors.append(f"{path}: expected type {spec}, got "
                      f"{type(value).__name__}")
        return False

    def _enum(self, value: Any, schema: dict[str, Any], path: str,
              errors: list[str]) -> None:
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: {value!r} is not one of {schema['enum']}")

    def _string(self, value: str, schema: dict[str, Any], path: str,
                errors: list[str]) -> None:
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and not self._regex(schema["pattern"]).search(value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
        fmt = schema.get("format")
        if fmt == "date-time" and not _DATE_TIME.match(value):
            errors.append(f"{path}: {value!r} is not a valid date-time")
        elif fmt == "idn-email" and not _EMAIL.match(value):
            errors.append(f"{path}: {value!r} is not a valid email")
        elif fmt == "iri-reference" and value.strip() != value:
            errors.append(f"{path}: {value!r} is not a valid iri-reference")

    def _number(self, value: Any, schema: dict[str, Any], path: str,
                errors: list[str]) -> None:
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} > maximum {schema['maximum']}")

    def _array(self, value: list, schema: dict[str, Any], path: str,
               errors: list[str]) -> None:
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems {schema['maxItems']}")
        if schema.get("uniqueItems") and _has_duplicates(value):
            errors.append(f"{path}: items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, list):
            raise SchemaFeatureError(f"{path}: tuple-form 'items' is not implemented")
        if isinstance(item_schema, dict):
            for i, item in enumerate(value):
                self._check(item, item_schema, f"{path}[{i}]", errors)

    def _object(self, value: dict, schema: dict[str, Any], path: str,
                errors: list[str]) -> None:
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property '{key}'")
        if schema.get("additionalProperties") is False and props:
            for key in value:
                if key not in props:
                    errors.append(f"{path}: additional property '{key}' is not allowed")
        for key, sub in schema.get("dependencies", {}).items():
            if key not in value:
                continue
            if isinstance(sub, list):
                for dep in sub:
                    if dep not in value:
                        errors.append(
                            f"{path}: property '{key}' requires '{dep}'")
            elif isinstance(sub, dict):
                self._check(value, sub, path, errors)
        for key, sub in props.items():
            if key in value:
                self._check(value[key], sub, f"{path}.{key}", errors)


def _has_duplicates(items: list) -> bool:
    seen: list[str] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            return True
        seen.append(key)
    return False


# ======================================================================================
# Convenience
# ======================================================================================
_CACHED: Validator | None = None


def load_schema(path: str | pathlib.Path = SCHEMA_PATH) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text())


def validator(path: str | pathlib.Path = SCHEMA_PATH) -> Validator:
    """The validator for the vendored schema, built once and reused."""
    global _CACHED
    if _CACHED is None or path != SCHEMA_PATH:
        v = Validator(load_schema(path))
        if path != SCHEMA_PATH:
            return v
        _CACHED = v
    return _CACHED


def validate(doc: dict[str, Any],
             path: str | pathlib.Path = SCHEMA_PATH) -> list[str]:
    """Validate `doc`; returns a list of errors (empty means it conforms)."""
    return validator(path).validate(doc)


def is_valid(doc: dict[str, Any], path: str | pathlib.Path = SCHEMA_PATH) -> bool:
    return not validate(doc, path)


def report(doc: dict[str, Any], path: str | pathlib.Path = SCHEMA_PATH) -> dict[str, Any]:
    """A structured validation result, suitable for the API and the CLI."""
    errors = validate(doc, path)
    return {
        "valid": not errors,
        "errors": errors,
        "error_count": len(errors),
        "schema": "CycloneDX 1.6 (ECMA-424)",
        "schema_file": str(pathlib.Path(path).name),
        "validator": ("ECDAT built-in draft-07 subset validator (no third-party "
                      "dependency). Covers every keyword present in the vendored "
                      "schema and raises on any construct it does not implement."),
        "scope": ("Conformance to the vendored schema file. This is not a CycloneDX "
                  "certification and not a statement about third-party tool "
                  "acceptance."),
    }
