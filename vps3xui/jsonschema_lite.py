"""A small, dependency-free JSON Schema subset validator.

Only the keywords used by the shipped ``config/manifest.schema.json`` and the
plan/backup schemas are implemented. Unknown keywords are ignored so the same
schema files stay usable by full JSON Schema tooling. Failures raise
``SchemaError`` with a bounded JSON pointer path, never with raw values.
"""

from __future__ import annotations

import re
from typing import Any, List


class SchemaError(Exception):
    def __init__(self, path: str, message: str):
        super(SchemaError, self).__init__("%s: %s" % (path or "/", message))
        self.path = path or "/"
        self.message = message


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def validate(instance: Any, schema: Any, path: str = "") -> None:
    if not isinstance(schema, dict):
        return

    if "type" in schema:
        expected = schema["type"]
        types: List[str] = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(instance, item) for item in types):
            raise SchemaError(
                path, "expected %s, got %s" % ("/".join(types), _json_type(instance))
            )

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaError(path, "value is not one of the allowed choices")

    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if pattern is not None and re.match(pattern, instance) is None:
            raise SchemaError(path, "string does not match required pattern")
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            raise SchemaError(path, "string is shorter than minLength")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(instance) > max_length:
            raise SchemaError(path, "string is longer than maxLength")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            raise SchemaError(path, "number is below minimum")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and instance > maximum:
            raise SchemaError(path, "number is above maximum")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            raise SchemaError(path, "array has fewer than minItems entries")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(instance) > max_items:
            raise SchemaError(path, "array has more than maxItems entries")
        if schema.get("uniqueItems"):
            seen = []
            for item in instance:
                if item in seen:
                    raise SchemaError(path, "array items are not unique")
                seen.append(item)
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate(item, item_schema, "%s/%d" % (path, index))

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                raise SchemaError(path, "missing required property %r" % key)
        properties = schema.get("properties", {})
        for key, sub_schema in properties.items():
            if key in instance:
                validate(instance[key], sub_schema, "%s/%s" % (path, key))
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in instance:
                if key not in properties:
                    raise SchemaError(path, "unexpected property %r" % key)
        elif isinstance(additional, dict):
            for key, value in instance.items():
                if key not in properties:
                    validate(value, additional, "%s/%s" % (path, key))

    if "oneOf" in schema:
        matches = 0
        for sub_schema in schema["oneOf"]:
            try:
                validate(instance, sub_schema, path)
                matches += 1
            except SchemaError:
                pass
        if matches != 1:
            raise SchemaError(path, "value must match exactly one schema")

    if "anyOf" in schema:
        for sub_schema in schema["anyOf"]:
            try:
                validate(instance, sub_schema, path)
                return
            except SchemaError:
                pass
        raise SchemaError(path, "value matches none of the allowed schemas")
