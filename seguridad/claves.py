import base64
import binascii
import os
import re
from typing import Protocol

from .errores import ClaveInvalida


class GestorClaves(Protocol):
    """Implementar este método para integrar un proveedor de secretos."""

    def obtener_clave(self, key_id: str | None = None) -> bytes: ...

    def obtener_id_clave_activa(self) -> str: ...


def validar_key_id(key_id: str) -> str:
    if type(key_id) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id) is None:
        raise ClaveInvalida("Identificador de clave inválido.")
    return key_id


def validar_clave(clave: bytes) -> bytes:
    if type(clave) is not bytes or len(clave) != 32:
        raise ClaveInvalida("Se requiere una clave de 32 bytes.")
    return clave


def generar_clave() -> str:
    """Devuelve una clave aleatoria de 256 bits codificada en Base64."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


class GestorClavesEntorno:
    def __init__(self, variable: str = "MODSEC_CLAVE", *, id_legacy: str = "KEY01"):
        self.variable = variable
        self.id_legacy = validar_key_id(id_legacy)

    def obtener_id_clave_activa(self) -> str:
        return validar_key_id(os.environ.get(self.variable + "_ACTIVA", self.id_legacy))

    def _cargar(self, variable: str) -> bytes:
        try:
            valor = os.environ[variable]
            if len(valor) != 44:
                raise ValueError
            clave = base64.b64decode(valor, validate=True)
        except (KeyError, ValueError, binascii.Error):
            raise ClaveInvalida("La variable de clave está ausente o es inválida.") from None
        return validar_clave(clave)

    def obtener_clave(self, key_id: str | None = None) -> bytes:
        key_id = self.obtener_id_clave_activa() if key_id is None else validar_key_id(key_id)
        variable = self.variable + "_" + key_id
        if variable in os.environ:
            return self._cargar(variable)
        if key_id == self.id_legacy:
            return self._cargar(self.variable)
        raise ClaveInvalida("Identificador de clave desconocido o sin configurar.")

    def obtener_clave_legacy(self) -> bytes:
        if self.variable in os.environ:
            return self._cargar(self.variable)
        return self.obtener_clave(self.id_legacy)

    def __repr__(self) -> str:
        return "GestorClavesEntorno(<configuración oculta>)"
