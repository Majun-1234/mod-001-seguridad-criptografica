"""HKDF de cryptography; parámetros fijos pertenecientes al formato v2."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .claves import validar_clave
from .errores import FormatoInvalido

SALT = b"MODSEC/v2/HKDF-SHA256"
CONTEXTOS = {"datos": b"MODSEC/v2/datos", "archivos": b"MODSEC/v2/archivos"}


def derivar_subclave(maestra: bytes, dominio: str) -> bytes:
    validar_clave(maestra)
    if dominio not in CONTEXTOS:
        raise FormatoInvalido("Dominio de derivación no admitido.")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=CONTEXTOS[dominio]).derive(maestra)
