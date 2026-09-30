"""Muestras guardadas de la implementación 1.0.0 anterior (clave pública de prueba)."""
import base64
import json
from pathlib import Path
import pytest
from seguridad import Seguridad, GestorClavesEntorno, DatosAlterados, ArchivoCorrupto, ClaveInvalida, generar_clave
from seguridad.formato import MAGIA_ARCHIVO

FIXTURES = Path(__file__).parent / "fixtures"
MUESTRA = json.loads((FIXTURES / "datos_v1.json").read_text(encoding="utf-8"))
VALOR = {"texto": "Histórico", "numero": 150000, "activo": True, "lista": [None, 1.5]}


@pytest.fixture
def legacy(monkeypatch):
    monkeypatch.setenv("MODSEC_CLAVE", MUESTRA["clave_prueba_publica"])
    monkeypatch.delenv("MODSEC_CLAVE_KEY01", raising=False)
    monkeypatch.delenv("MODSEC_CLAVE_ACTIVA", raising=False)
    return Seguridad()


def test_datos_v1(legacy):
    assert legacy.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"]) == VALOR
    assert legacy.cifrar(VALOR).startswith("MODSEC$2$KEY01$")


def test_archivo_v1(legacy, tmp_path):
    salida = tmp_path / "salida"
    legacy.descifrar_archivo(FIXTURES / "archivo_v1.bin", salida, contexto=MUESTRA["contexto"])
    assert salida.read_bytes() == b"MODSEC v1: documento de prueba\x00\xff"
    nueva = tmp_path / "nuevo"
    legacy.cifrar_archivo(salida, nueva)
    assert nueva.read_bytes()[len(MAGIA_ARCHIVO)] == 2


def test_v1_no_depende_de_activa(legacy, monkeypatch, tmp_path):
    monkeypatch.setenv("MODSEC_CLAVE_KEY02", generar_clave())
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", "KEY02")
    assert legacy.cifrar(1).startswith("MODSEC$2$KEY02$")
    assert legacy.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"]) == VALOR
    legacy.descifrar_archivo(FIXTURES / "archivo_v1.bin", tmp_path / "salida", contexto=MUESTRA["contexto"])


def test_v1_entorno_multiple_sin_variable_antigua(legacy, monkeypatch):
    monkeypatch.setenv("MODSEC_CLAVE_KEY01", MUESTRA["clave_prueba_publica"])
    monkeypatch.delenv("MODSEC_CLAVE")
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", "KEY02")
    monkeypatch.setenv("MODSEC_CLAVE_KEY02", generar_clave())
    assert legacy.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"]) == VALOR
    monkeypatch.delenv("MODSEC_CLAVE_KEY01")
    with pytest.raises(ClaveInvalida):
        legacy.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"])


def test_v1_clave_incorrecta(legacy, monkeypatch, tmp_path):
    monkeypatch.setenv("MODSEC_CLAVE", generar_clave())
    with pytest.raises(DatosAlterados):
        legacy.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"])
    with pytest.raises(ArchivoCorrupto):
        legacy.descifrar_archivo(FIXTURES / "archivo_v1.bin", tmp_path / "salida", contexto=MUESTRA["contexto"])


def test_v1_manipulado(legacy, tmp_path):
    partes = MUESTRA["cifrado"].split("$")
    bloque = bytearray(base64.b64decode(partes[3]))
    bloque[-1] ^= 1
    partes[3] = base64.b64encode(bloque).decode()
    with pytest.raises(DatosAlterados):
        legacy.descifrar("$".join(partes), contexto=MUESTRA["contexto"])
    archivo = tmp_path / "alterado"
    datos = bytearray((FIXTURES / "archivo_v1.bin").read_bytes())
    datos[-1] ^= 1
    archivo.write_bytes(datos)
    with pytest.raises(ArchivoCorrupto):
        legacy.descifrar_archivo(archivo, tmp_path / "salida", contexto=MUESTRA["contexto"])


def test_v1_contexto_incorrecto(legacy):
    with pytest.raises(DatosAlterados):
        legacy.descifrar(MUESTRA["cifrado"], contexto="otro")


def test_proveedor_v1_sigue_funcionando(monkeypatch):
    class ProveedorV1:
        def obtener_clave(self):
            return base64.b64decode(MUESTRA["clave_prueba_publica"])
    s = Seguridad(ProveedorV1())
    assert s.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"]) == VALOR
    assert s.descifrar(s.cifrar(1)) == 1
    with pytest.raises(ClaveInvalida):
        s.descifrar(s.cifrar(1).replace("KEY01", "KEY02"))


def test_id_legacy_personalizado(monkeypatch):
    monkeypatch.delenv("OTRA_CLAVE", raising=False)
    monkeypatch.setenv("OTRA_CLAVE_HISTORICA", MUESTRA["clave_prueba_publica"])
    s = Seguridad(GestorClavesEntorno("OTRA_CLAVE", id_legacy="HISTORICA"))
    assert s.descifrar(MUESTRA["cifrado"], contexto=MUESTRA["contexto"]) == VALOR
    assert s.cifrar(1).startswith("MODSEC$2$HISTORICA$")
