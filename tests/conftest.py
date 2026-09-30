import pytest
from seguridad import Seguridad, generar_clave


@pytest.fixture
def seguridad(monkeypatch):
    monkeypatch.setenv("MODSEC_CLAVE", generar_clave())
    return Seguridad()
