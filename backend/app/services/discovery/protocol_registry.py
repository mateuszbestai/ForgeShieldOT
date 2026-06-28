"""Map free-form protocol tokens and well-known ports to NormalizedProtocol.

This is the single normalization point so every adapter speaks the same protocol
vocabulary. Both a name token (e.g. "modbus", "enip") and a transport port
(e.g. 502, 44818) resolve to the same canonical enum value.
"""
from __future__ import annotations

from app.core.enums import NormalizedProtocol

# Canonical name tokens (lowercased) -> NormalizedProtocol.
_NAME_MAP: dict[str, NormalizedProtocol] = {
    "modbus": NormalizedProtocol.MODBUS_TCP,
    "modbus_tcp": NormalizedProtocol.MODBUS_TCP,
    "modbustcp": NormalizedProtocol.MODBUS_TCP,
    "s7": NormalizedProtocol.S7COMM,
    "s7comm": NormalizedProtocol.S7COMM,
    "iso-tsap": NormalizedProtocol.S7COMM,
    "enip": NormalizedProtocol.ETHERNET_IP_CIP,
    "ethernet_ip": NormalizedProtocol.ETHERNET_IP_CIP,
    "ethernetip": NormalizedProtocol.ETHERNET_IP_CIP,
    "cip": NormalizedProtocol.ETHERNET_IP_CIP,
    "opcua": NormalizedProtocol.OPC_UA,
    "opc_ua": NormalizedProtocol.OPC_UA,
    "opc-ua": NormalizedProtocol.OPC_UA,
    "dnp3": NormalizedProtocol.DNP3,
    "dnp": NormalizedProtocol.DNP3,
    "profinet": NormalizedProtocol.PROFINET,
    "pnio": NormalizedProtocol.PROFINET,
    "bacnet": NormalizedProtocol.BACNET,
    "iec104": NormalizedProtocol.IEC_60870_5_104,
    "iec-104": NormalizedProtocol.IEC_60870_5_104,
    "iec_60870_5_104": NormalizedProtocol.IEC_60870_5_104,
    "iec60870": NormalizedProtocol.IEC_60870_5_104,
    "mqtt": NormalizedProtocol.MQTT,
    "http": NormalizedProtocol.HTTP,
    "https": NormalizedProtocol.HTTPS,
    "tls": NormalizedProtocol.HTTPS,
    "smb": NormalizedProtocol.SMB,
    "cifs": NormalizedProtocol.SMB,
    "rdp": NormalizedProtocol.RDP,
    "ssh": NormalizedProtocol.SSH,
}

# Well-known transport ports -> NormalizedProtocol.
_PORT_MAP: dict[int, NormalizedProtocol] = {
    502: NormalizedProtocol.MODBUS_TCP,
    102: NormalizedProtocol.S7COMM,
    44818: NormalizedProtocol.ETHERNET_IP_CIP,
    4840: NormalizedProtocol.OPC_UA,
    20000: NormalizedProtocol.DNP3,
    34962: NormalizedProtocol.PROFINET,
    34964: NormalizedProtocol.PROFINET,
    47808: NormalizedProtocol.BACNET,
    2404: NormalizedProtocol.IEC_60870_5_104,
    1883: NormalizedProtocol.MQTT,
    8883: NormalizedProtocol.MQTT,
    80: NormalizedProtocol.HTTP,
    443: NormalizedProtocol.HTTPS,
    445: NormalizedProtocol.SMB,
    3389: NormalizedProtocol.RDP,
    22: NormalizedProtocol.SSH,
}


def normalize_protocol(token: str | None, port: int | None) -> NormalizedProtocol | None:
    """Resolve a protocol name token and/or port to a NormalizedProtocol.

    Name tokens take precedence over ports (the token is the more explicit signal),
    falling back to the well-known port mapping. Returns ``None`` if neither resolves.
    """
    if token:
        key = token.strip().lower().replace(" ", "").replace("/", "_")
        # Exact match first, then a couple of common, un-normalized variants.
        if key in _NAME_MAP:
            return _NAME_MAP[key]
        dashed = token.strip().lower()
        if dashed in _NAME_MAP:
            return _NAME_MAP[dashed]
    if port is not None and port in _PORT_MAP:
        return _PORT_MAP[port]
    return None
