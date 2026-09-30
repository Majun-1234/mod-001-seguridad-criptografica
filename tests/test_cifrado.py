import base64
from datetime import date, datetime, timezone
import pytest
from seguridad import DatosAlterados, FormatoInvalido, VersionNoSoportada, generar_clave


@pytest.mark.parametrize("valor", ["Información privada 🔒", "", 150000, -3, 1.25, True, False, None, ["A", "B"], {"rol": "Administrador", "anidado": [None, True, {"n": 2}]}, date(2026, 9, 30), datetime(2026, 9, 30, tzinfo=timezone.utc), {"fecha": date(2026, 9, 30)}, {"date": "2026-09-30"}])
def test_tipos(seguridad, valor):
    cifrado = seguridad.cifrar(valor)
    recuperado = seguridad.descifrar(cifrado)
    assert recuperado == valor
    assert type(recuperado) is type(valor)
    assert cifrado.startswith("MODSEC$2$KEY01$XCHACHA20$")
    assert seguridad.cifrar(valor) != cifrado


def test_contexto(seguridad):
    cifrado = seguridad.cifrar("dato", contexto="usuario.email")
    assert seguridad.descifrar(cifrado, contexto="usuario.email") == "dato"
    for contexto in ("", "usuario.nombre"):
        with pytest.raises(DatosAlterados):
            seguridad.descifrar(cifrado, contexto=contexto)


def test_manipulacion(seguridad):
    partes = seguridad.cifrar("dato").split("$")
    bloque = bytearray(base64.b64decode(partes[4]))
    bloque[-1] ^= 1
    partes[4] = base64.b64encode(bloque).decode()
    with pytest.raises(DatosAlterados):
        seguridad.descifrar("$".join(partes))


def test_clave_incorrecta(seguridad, monkeypatch):
    cifrado = seguridad.cifrar("dato")
    monkeypatch.setenv("MODSEC_CLAVE", generar_clave())
    with pytest.raises(DatosAlterados):
        seguridad.descifrar(cifrado)


@pytest.mark.parametrize("texto", ["", "otra", "MODSEC$1$OTRO$abc", "MODSEC$1$XCHACHA20$!!!!", "MODSEC$1$XCHACHA20$YQ==", None])
def test_formato(seguridad, texto):
    with pytest.raises(FormatoInvalido):
        seguridad.descifrar(texto)


def test_version(seguridad):
    with pytest.raises(VersionNoSoportada):
        seguridad.descifrar(seguridad.cifrar(1).replace("$2$", "$3$"))


@pytest.mark.parametrize("valor", [float("nan"), float("inf"), {1: "no"}, (1, 2), b"bytes", object()])
def test_tipos_no_admitidos(seguridad, valor):
    with pytest.raises(FormatoInvalido):
        seguridad.cifrar(valor)


def test_ciclo(seguridad):
    valor = []
    valor.append(valor)
    with pytest.raises(FormatoInvalido):
        seguridad.cifrar(valor)
