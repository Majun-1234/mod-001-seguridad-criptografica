import os
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError

from .claves import validar_clave
from .derivacion import derivar_subclave
from .errores import DatosAlterados
from .formato import prefijo_dato, codificar, decodificar, datos_asociados
from .limites import MAX_TAMANO_DATO
from .serializacion import serializar, deserializar


def cifrar(valor, clave: bytes, contexto: str = "", *, key_id: str = "KEY01", max_tamano: int = MAX_TAMANO_DATO) -> str:
    validar_clave(clave)
    nonce = os.urandom(24)
    aad = datos_asociados(prefijo_dato(key_id).encode("ascii"), contexto, max_tamano)
    subclave = derivar_subclave(clave, "datos")
    resultado = crypto_aead_xchacha20poly1305_ietf_encrypt(serializar(valor, max_tamano), aad, nonce, subclave)
    return codificar(nonce + resultado, key_id)


def descifrar(texto: str, resolver_clave, contexto: str = "", *, max_tamano: int = MAX_TAMANO_DATO):
    version, key_id, cabecera, datos = decodificar(texto, max_tamano)
    clave = validar_clave(resolver_clave(version, key_id))
    if version == 2:
        clave = derivar_subclave(clave, "datos")
    aad = datos_asociados(cabecera, contexto, max_tamano)
    try:
        original = crypto_aead_xchacha20poly1305_ietf_decrypt(datos[24:], aad, datos[:24], clave)
    except CryptoError:
        raise DatosAlterados("No se pudo autenticar el dato, la clave o el contexto.") from None
    return deserializar(original, max_tamano)
