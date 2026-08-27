"""Sigma Engine — Layer 3 (Hunt Runner / Detection Layer).

Converts a Sigma rule (YAML) into KQL (for Sentinel, via the official
sentinel_asim_pipeline) and EQL (for Elastic, via ORION's own
product-agnostic ECS field mapper).
"""
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.backends.elasticsearch import EqlBackend
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation


# ─────────────────────────────────────────────────────────────────
# ORION's ECS field mapper — product-agnostic, unlike pySigma's
# built-in ecs_windows (which is scoped to product: windows only).
# Maps Sigma's generic process_creation taxonomy to ECS field names.
# ─────────────────────────────────────────────────────────────────
_ECS_FIELD_MAPPING = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "Computer": "host.name",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
}

orion_ecs_pipeline = ProcessingPipeline(
    name="orion_generic_ecs",
    priority=20,
    items=[
        ProcessingItem(
            identifier="orion_field_mapping",
            transformation=FieldMappingTransformation(_ECS_FIELD_MAPPING),
        ),
    ],
)


class SigmaConversionError(Exception):
    """Raised when a Sigma rule fails to parse or convert."""
    pass


def convert_to_kql(rule_yaml: str) -> str:
    """Convert a Sigma rule to KQL for Sentinel, using the official
    ASIM pipeline. Returns the first generated query.
    """
    try:
        rules = SigmaCollection.from_yaml(rule_yaml)
        pipeline = sentinel_asim_pipeline()
        backend = KustoBackend(processing_pipeline=pipeline)
        queries = backend.convert(rules)
        return queries[0]
    except Exception as e:
        raise SigmaConversionError(f"KQL conversion failed: {e}") from e


def convert_to_eql(rule_yaml: str) -> str:
    """Convert a Sigma rule to EQL for Elastic, using ORION's
    product-agnostic ECS field mapper. Returns the first generated query.
    """
    try:
        rules = SigmaCollection.from_yaml(rule_yaml)
        backend = EqlBackend(processing_pipeline=orion_ecs_pipeline)
        queries = backend.convert(rules)
        return queries[0]
    except Exception as e:
        raise SigmaConversionError(f"EQL conversion failed: {e}") from e


def convert_sigma_rule(rule_yaml: str) -> dict:
    """Convert a Sigma rule to both KQL and EQL.

    Returns:
        {"kql": "...", "eql": "...", "kql_error": None, "eql_error": None}

    Both conversions are attempted independently — a failure in one
    backend doesn't block the other, since a rule might legitimately
    only make sense for one SIEM's log source.
    """
    result = {"kql": None, "eql": None, "kql_error": None, "eql_error": None}

    try:
        result["kql"] = convert_to_kql(rule_yaml)
    except SigmaConversionError as e:
        result["kql_error"] = str(e)

    try:
        result["eql"] = convert_to_eql(rule_yaml)
    except SigmaConversionError as e:
        result["eql_error"] = str(e)

    return result