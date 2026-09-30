"""Contenedor versionado de registros SecretStream, con memoria acotada."""
import os
import struct
import tempfile
from contextlib import contextmanager
from pathlib import Path

from nacl import bindings as sodium
from nacl.exceptions import CryptoError

from .claves import validar_clave, validar_key_id
from .derivacion import derivar_subclave
from .errores import ArchivoCorrupto, ErrorSeguridad, FormatoInvalido, VersionNoSoportada
from .formato import CABECERA_ARCHIVO_V1, MAGIA_ARCHIVO, ALGORITMO_ARCHIVO, datos_asociados, cabecera_archivo

TAMANO_BLOQUE = 1024 * 1024
SOBRECARGA = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
TAG_MENSAJE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL


@contextmanager
def _destino_seguro(entrada, salida):
    origen, destino = Path(entrada), Path(salida)
    if origen.resolve() == destino.resolve():
        raise ErrorSeguridad("La entrada y la salida deben ser distintas.")
    temporal = None
    try:
        if destino.exists():
            raise ErrorSeguridad("El destino ya existe.")
        with origen.open("rb") as fuente:
            with tempfile.NamedTemporaryFile(mode="wb", dir=destino.parent, prefix=".modsec-", delete=False) as archivo:
                temporal = Path(archivo.name)
                yield fuente, archivo
                archivo.flush()
                os.fsync(archivo.fileno())
            # Publicación sin sobrescritura, incluso si otro proceso creó el destino.
            os.link(temporal, destino)
    except OSError:
        raise ErrorSeguridad("No se pudo leer o escribir el archivo; revise rutas y permisos.") from None
    finally:
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def _leer(fuente, cantidad):
    datos = fuente.read(cantidad)
    if len(datos) != cantidad:
        raise ArchivoCorrupto("Archivo cifrado incompleto.")
    return datos


def cifrar_archivo(entrada, salida, clave: bytes, contexto: str = "", *, key_id: str = "KEY01"):
    validar_clave(clave)
    formato = cabecera_archivo(key_id)
    aad = datos_asociados(formato, contexto)
    clave = derivar_subclave(clave, "archivos")
    estado = sodium.crypto_secretstream_xchacha20poly1305_state()
    cabecera = sodium.crypto_secretstream_xchacha20poly1305_init_push(estado, clave)
    with _destino_seguro(entrada, salida) as (fuente, destino):
        destino.write(formato + cabecera)
        while True:
            bloque = fuente.read(TAMANO_BLOQUE)
            tag = TAG_MENSAJE if bloque else TAG_FINAL
            cifrado = sodium.crypto_secretstream_xchacha20poly1305_push(estado, bloque, ad=aad, tag=tag)
            destino.write(struct.pack(">I", len(cifrado)))
            destino.write(cifrado)
            if tag == TAG_FINAL:
                break


def descifrar_archivo(entrada, salida, resolver_clave, contexto: str = ""):
    with _destino_seguro(entrada, salida) as (fuente, destino):
        if _leer(fuente, len(MAGIA_ARCHIVO)) != MAGIA_ARCHIVO:
            raise FormatoInvalido("No es un archivo MODSEC.")
        version = _leer(fuente, 1)
        if version not in (b"\x01", b"\x02"):
            raise VersionNoSoportada("Versión de archivo no soportada.")
        if _leer(fuente, len(ALGORITMO_ARCHIVO)) != ALGORITMO_ARCHIVO:
            raise FormatoInvalido("Algoritmo de archivo no soportado.")
        key_id = None
        formato = CABECERA_ARCHIVO_V1
        if version == b"\x02":
            longitud = _leer(fuente, 1)[0]
            if not 1 <= longitud <= 64:
                raise FormatoInvalido("Identificador de archivo inválido.")
            try:
                key_id = validar_key_id(_leer(fuente, longitud).decode("ascii"))
            except UnicodeError:
                raise FormatoInvalido("Identificador de archivo inválido.") from None
            formato = cabecera_archivo(key_id)
        clave = validar_clave(resolver_clave(version[0], key_id))
        if version == b"\x02":
            clave = derivar_subclave(clave, "archivos")
        aad = datos_asociados(formato, contexto)
        cabecera = _leer(fuente, sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
        estado = sodium.crypto_secretstream_xchacha20poly1305_state()
        try:
            sodium.crypto_secretstream_xchacha20poly1305_init_pull(estado, cabecera, clave)
            while True:
                cantidad = struct.unpack(">I", _leer(fuente, 4))[0]
                if not SOBRECARGA <= cantidad <= TAMANO_BLOQUE + SOBRECARGA:
                    raise ArchivoCorrupto("Longitud de bloque inválida.")
                bloque, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(estado, _leer(fuente, cantidad), ad=aad)
                if tag == TAG_FINAL:
                    if bloque or fuente.read(1):
                        raise ArchivoCorrupto("Final de archivo inválido.")
                    break
                if tag != TAG_MENSAJE or not bloque:
                    raise ArchivoCorrupto("Secuencia de bloques inválida.")
                destino.write(bloque)
        except CryptoError:
            raise ArchivoCorrupto("No se pudo autenticar el archivo, la clave o el contexto.") from None
