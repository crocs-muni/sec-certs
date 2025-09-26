import json
from importlib import resources

from jsonschema import Draft7Validator
from referencing import Registry, Resource

_schemas = ["base.json", "cc_certificate.json", "cc_dataset.json", "fips_certificate.json", "fips_dataset.json"]


def validator(for_schema: str) -> Draft7Validator:
    registry = Registry()
    for schema in _schemas:
        with resources.open_text("sec_certs.serialization.schemas", schema) as f:
            schema_json = json.load(f)
            resource = Resource.from_contents(schema_json)
            registry = resource @ registry
    return Draft7Validator(schema={"$ref": for_schema}, registry=registry)
