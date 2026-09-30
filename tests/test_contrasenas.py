import pytest
from argon2 import PasswordHasher
from seguridad import Seguridad, FormatoInvalido


def test_hash_verificacion_y_salts(monkeypatch):
    monkeypatch.delenv("MODSEC_CLAVE", raising=False)
    s = Seguridad()
    h = s.hash_contraseña("clave privada")
    assert h.startswith("$argon2id$")
    assert s.verificar_contraseña("clave privada", h)
    assert not s.verificar_contraseña("incorrecta", h)
    assert s.hash_contraseña("clave privada") != h
    assert not s.necesita_actualizacion(h)


def test_rehash(seguridad):
    anterior = PasswordHasher(time_cost=1, memory_cost=8192).hash("clave")
    assert seguridad.verificar_contraseña("clave", anterior)
    assert seguridad.necesita_actualizacion(anterior)


@pytest.mark.parametrize("hash_guardado", ["inválido", "", None, "$argon2id$roto"])
def test_hash_invalido(seguridad, hash_guardado):
    with pytest.raises(FormatoInvalido):
        seguridad.verificar_contraseña("clave", hash_guardado)
    with pytest.raises(FormatoInvalido):
        seguridad.necesita_actualizacion(hash_guardado)
