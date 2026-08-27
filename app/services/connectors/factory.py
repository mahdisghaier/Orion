"""Connector factory — builds a connector instance from a SIEMConnection DB record."""
from app.models import SIEMConnection
from app.services.connectors.base import BaseSIEMConnector
from app.services.connectors.elastic import ElasticConnector

try:
    from app.core.crypto import decrypt_config
except ImportError:
    from app.core.encryption import decrypt_config


class ConnectorError(Exception):
    pass


def get_connector(conn: SIEMConnection) -> BaseSIEMConnector:
    if isinstance(conn.config_encrypted, str):
        config = decrypt_config(conn.config_encrypted)
    elif isinstance(conn.config_encrypted, dict) and "encrypted" in conn.config_encrypted:
        config = decrypt_config(conn.config_encrypted["encrypted"])
    elif isinstance(conn.config_encrypted, dict):
        config = conn.config_encrypted
    else:
        raise ConnectorError(f"Cannot parse config for connection {conn.id}")

    if conn.type == "elastic":
        return ElasticConnector(
            cluster_url=config.get("url", "http://localhost:9200"),
            api_key=config.get("api_key"),
            index_pattern=config.get("index_pattern", "logs-*"),
        )
    elif conn.type == "sentinel":
        raise ConnectorError("Sentinel connector not yet implemented")
    else:
        raise ConnectorError(f"Unsupported SIEM type: {conn.type}")
