import base64
import pytest
from seguridad import Seguridad, GestorClavesEntorno, ClaveInvalida, DatosAlterados, ArchivoCorrupto, generar_clave
from seguridad.formato import cabecera_archivo


@pytest.fixture
def gestor(monkeypatch):
    monkeypatch.delenv("MODSEC_CLAVE", raising=False)
    monkeypatch.setenv("MODSEC_CLAVE_KEY01", generar_clave())
    monkeypatch.setenv("MODSEC_CLAVE_KEY02", generar_clave())
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", "KEY01")
    return GestorClavesEntorno()


def test_rotacion_datos(gestor, monkeypatch):
    s = Seguridad(gestor)
    antiguo = s.cifrar({"valor": 1}, contexto="registro")
    assert antiguo.startswith("MODSEC$2$KEY01$")
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", "KEY02")
    nuevo = s.cifrar({"valor": 2}, contexto="registro")
    assert nuevo.startswith("MODSEC$2$KEY02$")
    assert s.descifrar(antiguo, contexto="registro") == {"valor": 1}
    assert s.descifrar(nuevo, contexto="registro") == {"valor": 2}
    assert gestor.obtener_clave() == gestor.obtener_clave("KEY02")
    assert gestor.obtener_clave("KEY01") != gestor.obtener_clave("KEY02")
    monkeypatch.delenv("MODSEC_CLAVE_KEY01")
    with pytest.raises(ClaveInvalida):
        s.descifrar(antiguo, contexto="registro")
    assert s.descifrar(nuevo, contexto="registro") == {"valor": 2}


def test_rotacion_archivos(gestor, monkeypatch, tmp_path):
    s = Seguridad(gestor)
    original = tmp_path / "original"
    original.write_bytes(b"documento")
    antiguo, nuevo = tmp_path / "antiguo", tmp_path / "nuevo"
    s.cifrar_archivo(original, antiguo, contexto="archivo")
    assert antiguo.read_bytes().startswith(cabecera_archivo("KEY01"))
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", "KEY02")
    s.cifrar_archivo(original, nuevo, contexto="archivo")
    assert nuevo.read_bytes().startswith(cabecera_archivo("KEY02"))
    for indice, archivo in enumerate((antiguo, nuevo)):
        salida = tmp_path / str(indice)
        s.descifrar_archivo(archivo, salida, contexto="archivo")
        assert salida.read_bytes() == original.read_bytes()


def test_id_desconocido(gestor):
    s = Seguridad(gestor)
    with pytest.raises(ClaveInvalida):
        s.descifrar(s.cifrar(1).replace("KEY01", "OTRA"))


def test_id_autenticado_datos(gestor, monkeypatch):
    # Incluso si dos IDs apuntan a la misma maestra, el ID está ligado por AAD.
    monkeypatch.setenv("MODSEC_CLAVE_KEY02", base64.b64encode(gestor.obtener_clave("KEY01")).decode())
    s = Seguridad(gestor)
    with pytest.raises(DatosAlterados):
        s.descifrar(s.cifrar(1).replace("KEY01", "KEY02"))


def test_id_autenticado_archivos(gestor, monkeypatch, tmp_path):
    monkeypatch.setenv("MODSEC_CLAVE_KEY02", base64.b64encode(gestor.obtener_clave("KEY01")).decode())
    s = Seguridad(gestor)
    origen, cifrado, salida = (tmp_path / n for n in ("origen", "cifrado", "salida"))
    origen.write_bytes(b"documento")
    s.cifrar_archivo(origen, cifrado)
    cifrado.write_bytes(cifrado.read_bytes().replace(b"KEY01", b"KEY02", 1))
    with pytest.raises(ArchivoCorrupto):
        s.descifrar_archivo(cifrado, salida)
    assert not salida.exists()


def test_id_desconocido_archivo(gestor, tmp_path):
    s = Seguridad(gestor)
    origen, cifrado, salida = (tmp_path / n for n in ("origen", "cifrado", "salida"))
    origen.write_bytes(b"dato")
    s.cifrar_archivo(origen, cifrado)
    cifrado.write_bytes(cifrado.read_bytes().replace(b"KEY01", b"KEY99", 1))
    with pytest.raises(ClaveInvalida):
        s.descifrar_archivo(cifrado, salida)
    assert not salida.exists()
    assert not list(tmp_path.glob(".modsec-*"))


@pytest.mark.parametrize("key_id", ["", "A$B", "A" * 65, "CLAVÉ", "../otra", "A\x00B"])
def test_id_invalido(gestor, monkeypatch, key_id):
    monkeypatch.setenv("MODSEC_CLAVE_ACTIVA", key_id) if "\x00" not in key_id else None
    with pytest.raises(ClaveInvalida):
        gestor.obtener_clave(key_id)


def test_proveedor_moderno_por_id():
    class Proveedor:
        def __init__(self):
            self.activa = "KEY01"
            self.claves = {"KEY01": b"a" * 32, "KEY02": b"b" * 32}
            self.consultas = []
        def obtener_id_clave_activa(self):
            return self.activa
        def obtener_clave(self, key_id):
            self.consultas.append(key_id)
            return self.claves[key_id]
    gestor = Proveedor()
    s = Seguridad(gestor)
    antiguo = s.cifrar(1)
    gestor.activa = "KEY02"
    nuevo = s.cifrar(2)
    assert s.descifrar(antiguo) == 1 and s.descifrar(nuevo) == 2
    assert gestor.consultas == ["KEY01", "KEY02", "KEY01", "KEY02"]
