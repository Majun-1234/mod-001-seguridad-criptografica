import hashlib
import os
import struct
import pytest
from seguridad import ArchivoCorrupto, ErrorSeguridad, generar_clave, VersionNoSoportada
from seguridad import archivos
from seguridad.formato import cabecera_archivo, MAGIA_ARCHIVO


@pytest.mark.parametrize("tamano", [0, 37, archivos.TAMANO_BLOQUE, archivos.TAMANO_BLOQUE * 5 + 137])
def test_recuperacion_y_streaming(seguridad, tmp_path, monkeypatch, tamano):
    original, cifrado, salida = (tmp_path / n for n in ("original", "cifrado", "salida"))
    datos = os.urandom(tamano)
    original.write_bytes(datos)
    lecturas = []
    leer = archivos._leer
    def comprobar(fuente, cantidad):
        lecturas.append(cantidad)
        assert 0 < cantidad <= archivos.TAMANO_BLOQUE + archivos.SOBRECARGA
        return leer(fuente, cantidad)
    monkeypatch.setattr(archivos, "_leer", comprobar)
    longitudes = []
    push = archivos.sodium.crypto_secretstream_xchacha20poly1305_push
    def comprobar_push(estado, bloque, **kwargs):
        longitudes.append(len(bloque))
        assert len(bloque) <= archivos.TAMANO_BLOQUE
        return push(estado, bloque, **kwargs)
    monkeypatch.setattr(archivos.sodium, "crypto_secretstream_xchacha20poly1305_push", comprobar_push)
    seguridad.cifrar_archivo(original, cifrado, contexto="documento")
    seguridad.descifrar_archivo(cifrado, salida, contexto="documento")
    assert salida.read_bytes() == datos
    assert hashlib.sha256(datos).digest() == hashlib.sha256(salida.read_bytes()).digest()
    assert lecturas and longitudes[-1] == 0
    assert len(longitudes) == (tamano + archivos.TAMANO_BLOQUE - 1) // archivos.TAMANO_BLOQUE + 1


@pytest.mark.parametrize("ataque", ["alterado", "truncado", "sin_final", "extra", "clave", "contexto", "longitud", "reordenado"])
def test_corrupcion_no_publica_salida(seguridad, tmp_path, monkeypatch, ataque):
    original, cifrado, salida = (tmp_path / n for n in ("original", "cifrado", "salida"))
    original.write_bytes(os.urandom(archivos.TAMANO_BLOQUE + 100))
    seguridad.cifrar_archivo(original, cifrado)
    datos = bytearray(cifrado.read_bytes())
    offset = len(cabecera_archivo("KEY01")) + 24
    if ataque == "alterado":
        datos[offset + 10] ^= 1
    elif ataque == "truncado":
        datos = datos[:-1]
    elif ataque == "sin_final":
        datos = datos[:-(4 + archivos.SOBRECARGA)]
    elif ataque == "extra":
        datos += b"x"
    elif ataque == "clave":
        monkeypatch.setenv("MODSEC_CLAVE", generar_clave())
    elif ataque == "longitud":
        datos[offset:offset + 4] = b"\xff" * 4
    elif ataque == "reordenado":
        primero = struct.unpack(">I", datos[offset:offset + 4])[0] + 4
        segundo = struct.unpack(">I", datos[offset + primero:offset + primero + 4])[0] + 4
        datos = datos[:offset] + datos[offset + primero:offset + primero + segundo] + datos[offset:offset + primero] + datos[offset + primero + segundo:]
    cifrado.write_bytes(datos)
    with pytest.raises(ArchivoCorrupto):
        seguridad.descifrar_archivo(cifrado, salida, contexto="incorrecto" if ataque == "contexto" else "")
    assert not salida.exists()
    assert not list(tmp_path.glob(".modsec-*"))


def test_no_sobrescribe(seguridad, tmp_path):
    original, destino = tmp_path / "original", tmp_path / "destino"
    original.write_bytes(b"original")
    destino.write_bytes(b"conservar")
    with pytest.raises(ErrorSeguridad):
        seguridad.cifrar_archivo(original, destino)
    with pytest.raises(ErrorSeguridad):
        seguridad.cifrar_archivo(original, original)
    assert original.read_bytes() == b"original"
    assert destino.read_bytes() == b"conservar"


def test_version_archivo(seguridad, tmp_path):
    origen, cifrado = tmp_path / "origen", tmp_path / "cifrado"
    origen.write_bytes(b"dato")
    seguridad.cifrar_archivo(origen, cifrado)
    datos = bytearray(cifrado.read_bytes())
    datos[len(MAGIA_ARCHIVO)] = 3
    cifrado.write_bytes(datos)
    with pytest.raises(VersionNoSoportada):
        seguridad.descifrar_archivo(cifrado, tmp_path / "salida")
