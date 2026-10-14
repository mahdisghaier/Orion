"""Sigma Engine — Layer 3 (Hunt Runner / Detection Layer).

Converts a Sigma rule (YAML) into KQL (for Sentinel, via the official
sentinel_asim_pipeline), EQL (for Elastic, via ORION's own
product-agnostic ECS field mapper) and Lucene (for Wazuh, via a field map
derived from real Wazuh alerts).
"""
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.transformations import FieldMappingTransformation, ValueTransformation
from sigma.types import SigmaString


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
    "TargetFilename": "file.path",
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


# ─────────────────────────────────────────────────────────────────
# Wazuh field map (Lucene on wazuh-alerts-*).
#
# Wazuh indexes ALERTS, not raw telemetry, and its fields are not ECS.
# This map is derived from real alerts collected in the lab (see
# docs/ in the thesis): only Sigma fields that exist in some Wazuh alert
# type are mapped. Everything else (ParentImage, ProcessId, ...) has no
# Wazuh counterpart, so a rule using it is reported as "not runnable"
# instead of silently returning 0 hits.
#
#   Image        -> full_log    text field, tokenised on "/" and spaces; the
#                               process name appears in the netstat alert
#                               (rule 533) as "<pid>/<name>". Matched by
#                               basename token, see _BasenameToken below.
#   CommandLine  -> data.command  keyword; present on sudo alerts (rule 5403)
#   User         -> data.srcuser  keyword; sudo / PAM alerts
#   Computer     -> agent.name    keyword
#   TargetFilename -> syscheck.path  keyword; file-integrity alerts (rules 550/553/554)
# ─────────────────────────────────────────────────────────────────
_WAZUH_FIELD_MAPPING = {
    "Image": "full_log",
    "CommandLine": "data.command",
    "User": "data.srcuser",
    "Computer": "agent.name",
    "TargetFilename": "syscheck.path",
    "SourceIp": "data.srcip",
    "DestinationIp": "data.dstip",
}

# Sigma fields each SIEM profile can express. Used for runnable / not-runnable.
SIEM_FIELD_PROFILES = {
    "elastic": frozenset(_ECS_FIELD_MAPPING),
    "wazuh": frozenset(_WAZUH_FIELD_MAPPING),
}


class _BasenameToken(ValueTransformation):
    """Reduce a path-like Sigma value to its basename token.

    full_log is an analysed text field: the index holds the term "nc", never
    "/usr/bin/nc", so pySigma's default wildcard "*\\/nc" matches nothing.
    "*/nc", "/usr/bin/nc" and "nc" all become the exact term "nc" (case-insensitive
    through the analyser). This is deliberately broader than the original
    endswith/contains semantics; it is the best a text field allows.
    """

    def apply_value(self, field, val):
        if not isinstance(val, SigmaString):
            return None
        plain = "".join(part for part in val.s if isinstance(part, str))
        base = plain.replace("\\", "/").rstrip("/").split("/")[-1].strip()
        return SigmaString(base) if base else None


orion_wazuh_pipeline = ProcessingPipeline(
    name="orion_wazuh_lucene",
    priority=20,
    items=[
        ProcessingItem(
            identifier="orion_wazuh_field_mapping",
            transformation=FieldMappingTransformation(_WAZUH_FIELD_MAPPING),
        ),
        ProcessingItem(
            identifier="orion_wazuh_basename_token",
            transformation=_BasenameToken(),
            field_name_conditions=[IncludeFieldCondition(fields=["full_log"])],
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


def convert_to_lucene(rule_yaml: str) -> str:
    """Convert a Sigma rule to a Lucene query_string for the Wazuh indexer.
    Returns the first generated query.
    """
    try:
        rules = SigmaCollection.from_yaml(rule_yaml)
        backend = LuceneBackend(processing_pipeline=orion_wazuh_pipeline)
        queries = backend.convert(rules)
        return queries[0]
    except Exception as e:
        raise SigmaConversionError(f"Lucene conversion failed: {e}") from e


def rule_fields(rule_yaml: str) -> set:
    """Field names used by a rule's detections (unfielded keyword searches excluded)."""
    def walk(node):
        for item in node.detection_items:
            if hasattr(item, "detection_items"):
                yield from walk(item)
            elif item.field:
                yield item.field

    fields = set()
    for rule in SigmaCollection.from_yaml(rule_yaml).rules:
        for detection in rule.detection.detections.values():
            fields.update(walk(detection))
    return fields


def unmapped_fields(rule_yaml: str, siem_type: str) -> list:
    """Sigma fields the rule uses that this SIEM profile cannot express.

    A non-empty result means the rule is NOT RUNNABLE on that SIEM: running
    it would return 0 hits for the wrong reason (blind spot, not clean data).
    Unknown SIEM types have no profile and report nothing.
    """
    profile = SIEM_FIELD_PROFILES.get(siem_type)
    if profile is None:
        return []
    try:
        return sorted(rule_fields(rule_yaml) - profile)
    except Exception:
        return []


def convert_sigma_rule(rule_yaml: str) -> dict:
    """Convert a Sigma rule to both KQL and EQL.

    Returns:
        {"kql": ..., "eql": ..., "lucene": ..., "<kind>_error": ...}

    Both conversions are attempted independently — a failure in one
    backend doesn't block the other, since a rule might legitimately
    only make sense for one SIEM's log source.
    """
    result = {
        "kql": None, "eql": None, "lucene": None,
        "kql_error": None, "eql_error": None, "lucene_error": None,
    }

    try:
        result["kql"] = convert_to_kql(rule_yaml)
    except SigmaConversionError as e:
        result["kql_error"] = str(e)

    try:
        result["eql"] = convert_to_eql(rule_yaml)
    except SigmaConversionError as e:
        result["eql_error"] = str(e)

    try:
        result["lucene"] = convert_to_lucene(rule_yaml)
    except SigmaConversionError as e:
        result["lucene_error"] = str(e)

    return result
