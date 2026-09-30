import base64
import pytest
from seguridad import ClaveInvalida, GestorClavesEntorno, Seguridad, generar_clave


def test_generacion_y_entorno(monkeypatch):
    clave = generar_clave()
    assert len(base64.b64decode(clave)) == 32
    assert clave != generar_clave()
    monkeypatch.setenv("MI_CLAVE", clave)
    gestor = GestorClavesEntorno("MI_CLAVE")
    assert gestor.obtener_clave() == base64.b64decode(clave)
    assert clave not in repr(gestor)
    assert clave not in repr(Seguridad(gestor))


@pytest.mark.parametrize("valor", [None, "", "secreto inválido", "!!!!", base64.b64encode(b"corta").decode()])
def test_clave_invalida(monkeypatch, valor):
    if valor is None:
        monkeypatch.delenv("MODSEC_CLAVE", raising=False)
    else:
        monkeypatch.setenv("MODSEC_CLAVE", valor)
    with pytest.raises(ClaveInvalida) as error:
        GestorClavesEntorno().obtener_clave()
    if valor:
        assert valor not in str(error.value)


def test_proveedor_personalizado():
    class Proveedor:
        def obtener_clave(self):
            return b"x" * 32
    s = Seguridad(Proveedor())
    assert s.descifrar(s.cifrar(123)) == 123


def test_proveedor_invalido():
    class Proveedor:
        def obtener_clave(self):
            return "clave accidental"
    with pytest.raises(ClaveInvalida):
        Seguridad(Proveedor()).cifrar("texto")
