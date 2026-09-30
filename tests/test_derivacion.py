import os
import pytest
from nacl import bindings as sodium
from nacl.exceptions import CryptoError
from seguridad.derivacion import derivar_subclave
from seguridad import ClaveInvalida, FormatoInvalido


def test_separacion_determinismo():
    maestra = os.urandom(32)
    datos = derivar_subclave(maestra, "datos")
    archivos = derivar_subclave(maestra, "archivos")
    assert len(datos) == len(archivos) == 32
    assert datos != archivos and datos != maestra and archivos != maestra
    assert datos == derivar_subclave(maestra, "datos")
    assert archivos == derivar_subclave(maestra, "archivos")
    assert datos != derivar_subclave(os.urandom(32), "datos")


def test_subclave_datos_no_abre_stream():
    maestra = os.urandom(32)
    push = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(push, derivar_subclave(maestra, "archivos"))
    bloque = sodium.crypto_secretstream_xchacha20poly1305_push(push, b"documento", tag=sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
    pull = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(pull, header, derivar_subclave(maestra, "datos"))
    with pytest.raises(CryptoError):
        sodium.crypto_secretstream_xchacha20poly1305_pull(pull, bloque)


def test_dominios_invalidos():
    with pytest.raises(FormatoInvalido):
        derivar_subclave(os.urandom(32), "contraseñas")
    with pytest.raises(ClaveInvalida):
        derivar_subclave(b"corta", "datos")
