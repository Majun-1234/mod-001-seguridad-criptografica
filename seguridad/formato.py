import base64
import binascii

from .claves import validar_key_id
from .errores import FormatoInvalido, VersionNoSoportada
from .limites import MAX_TAMANO_DATO, comprobar_tamano

PREFIJO = "MODSEC$1$XCHACHA20$"  # AAD histórica, sólo para lectura v1.
MAGIA_ARCHIVO = b"MODSECFILE\x00"
VERSION_ARCHIVO = b"\x02"
ALGORITMO_ARCHIVO = b"SECRETSTREAM\x00"
CABECERA_ARCHIVO_V1 = MAGIA_ARCHIVO + b"\x01" + ALGORITMO_ARCHIVO
CABECERA_ARCHIVO = MAGIA_ARCHIVO + VERSION_ARCHIVO + ALGORITMO_ARCHIVO


def prefijo_dato(key_id: str) -> str:
    return "MODSEC$2$" + validar_key_id(key_id) + "$XCHACHA20$"


def cabecera_archivo(key_id: str) -> bytes:
    identificador = validar_key_id(key_id).encode("ascii")
    return CABECERA_ARCHIVO + bytes([len(identificador)]) + identificador


def datos_asociados(cabecera: bytes, contexto: str, max_tamano: int = MAX_TAMANO_DATO) -> bytes:
    if type(contexto) is not str:
        raise FormatoInvalido("El contexto debe ser texto.")
    comprobar_tamano(len(contexto), max_tamano)
    try:
        contexto_bytes = contexto.encode("utf-8")
    except UnicodeError:
        raise FormatoInvalido("Contexto inválido.") from None
    comprobar_tamano(len(contexto_bytes), max_tamano)
    return cabecera + b"\x00" + contexto_bytes


def codificar(datos: bytes, key_id: str) -> str:
    return prefijo_dato(key_id) + base64.b64encode(datos).decode("ascii")


def decodificar(texto: str, max_tamano: int = MAX_TAMANO_DATO):
    """Retorna versión, ID (None para v1), AAD de cabecera y bytes cifrados."""
    if type(texto) is not str:
        raise FormatoInvalido("El valor cifrado debe ser texto.")
    max_base64 = 4 * ((max_tamano + 40 + 2) // 3)
    # Comprobar antes de split y Base64; el ID tiene como máximo 64 caracteres.
    comprobar_tamano(len(texto), max_base64 + 85)
    partes = texto.split("$", 4)
    if partes[0] != "MODSEC" or len(partes) < 4:
        raise FormatoInvalido("Formato cifrado inválido.")
    version = partes[1]
    if version not in ("1", "2"):
        raise VersionNoSoportada("Versión de datos no soportada.")
    if version == "1":
        if len(partes) != 4 or partes[2] != "XCHACHA20":
            raise FormatoInvalido("Formato cifrado inválido.")
        key_id, prefijo, contenido = None, PREFIJO, partes[3]
    else:
        if len(partes) != 5 or partes[3] != "XCHACHA20":
            raise FormatoInvalido("Formato cifrado inválido.")
        key_id = validar_key_id(partes[2])
        prefijo, contenido = prefijo_dato(key_id), partes[4]
    comprobar_tamano(len(contenido), max_base64)
    try:
        datos = base64.b64decode(contenido, validate=True)
    except (ValueError, binascii.Error):
        raise FormatoInvalido("Codificación inválida.") from None
    if len(datos) < 40:
        raise FormatoInvalido("Valor cifrado incompleto.")
    comprobar_tamano(len(datos) - 40, max_tamano)
    return int(version), key_id, prefijo.encode("ascii"), datos
