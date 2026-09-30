import base64
import pytest
from seguridad import Seguridad, TamanoExcedido, FormatoInvalido
from seguridad import formato, serializacion


def test_limite_exacto(seguridad):
    valor = "dato"
    tamano = len(serializacion.serializar(valor))
    s = Seguridad(max_tamano_dato=tamano)
    assert s.descifrar(s.cifrar(valor)) == valor
    menor = Seguridad(max_tamano_dato=tamano - 1)
    with pytest.raises(TamanoExcedido):
        menor.cifrar(valor)
    with pytest.raises(TamanoExcedido):
        menor.descifrar(seguridad.cifrar(valor))


def test_base64_rechazado_antes_de_decodificar(seguridad, monkeypatch):
    def prohibido(*args, **kwargs):
        pytest.fail("Base64 no debe ejecutarse para un payload excesivo")
    monkeypatch.setattr(formato.base64, "b64decode", prohibido)
    with pytest.raises(TamanoExcedido):
        Seguridad(max_tamano_dato=32).descifrar("MODSEC$2$KEY01$XCHACHA20$" + "A" * 2000)


def test_base64_contenido_excesivo_antes_de_decodificar(seguridad, monkeypatch):
    # Supera el límite de Base64 pero cabe bajo el límite de contenedor total.
    def prohibido(*args, **kwargs):
        pytest.fail("El contenido excesivo debe rechazarse antes de Base64")
    monkeypatch.setattr(formato.base64, "b64decode", prohibido)
    with pytest.raises(TamanoExcedido):
        Seguridad(max_tamano_dato=32).descifrar("MODSEC$2$KEY01$XCHACHA20$" + "A" * 100)


def test_json_rechazado_antes_de_parsear(monkeypatch):
    def prohibido(*args, **kwargs):
        pytest.fail("JSON no debe ejecutarse para un dato excesivo")
    monkeypatch.setattr(serializacion.json, "loads", prohibido)
    with pytest.raises(TamanoExcedido):
        serializacion.deserializar(b"x" * 100, max_tamano=10)


@pytest.mark.parametrize("valor", ["A" * 1000, [1] * 1000, {"a": "A" * 1000}, "🔒" * 20])
def test_serializacion_excesiva(seguridad, valor):
    with pytest.raises(TamanoExcedido):
        Seguridad(max_tamano_dato=64).cifrar(valor)


@pytest.mark.parametrize("limite", [0, -1, True, 1.5, "10", None])
def test_configuracion_invalida(limite):
    with pytest.raises(FormatoInvalido):
        Seguridad(max_tamano_dato=limite)


def test_streaming_independiente_del_limite(seguridad, tmp_path):
    s = Seguridad(max_tamano_dato=1)
    origen, cifrado, salida = (tmp_path / n for n in ("origen", "cifrado", "salida"))
    origen.write_bytes(b"documento" * 300000)
    s.cifrar_archivo(origen, cifrado)
    s.descifrar_archivo(cifrado, salida)
    assert salida.read_bytes() == origen.read_bytes()


def test_escape_rechazado_antes_de_crear_json(monkeypatch):
    def prohibido(*args, **kwargs):
        pytest.fail("No crear un escape JSON que ya supera el límite")
    monkeypatch.setattr(serializacion.json, "dumps", prohibido)
    with pytest.raises(TamanoExcedido):
        serializacion.serializar("🔒" * 20, max_tamano=64)


def test_limite_predeterminado(seguridad):
    assert seguridad.max_tamano_dato == 10 * 1024 * 1024


def test_contexto_acotado(seguridad):
    with pytest.raises(TamanoExcedido):
        Seguridad(max_tamano_dato=16).cifrar(1, contexto="A" * 17)


@pytest.mark.parametrize("valor", ['comillas"\\', "\b\f\n\r\t", "\x00\x7f", "á漢🔒", "\ud800"])
def test_limite_exacto_con_escapes(seguridad, valor):
    esperado = serializacion.json.dumps(["str", valor], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    assert serializacion.serializar(valor, max_tamano=len(esperado)) == esperado
    s = Seguridad(max_tamano_dato=len(esperado))
    assert s.descifrar(s.cifrar(valor)) == valor
    with pytest.raises(TamanoExcedido):
        s = Seguridad(max_tamano_dato=len(esperado) - 1)
        s.cifrar(valor)
