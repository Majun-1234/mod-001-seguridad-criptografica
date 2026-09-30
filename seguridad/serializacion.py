"""JSON etiquetado recursivo: sin pickle ni ejecución de código."""
import json
import math
from datetime import date, datetime

from .errores import FormatoInvalido
from .limites import MAX_TAMANO_DATO, comprobar_tamano


def _texto_json(valor, limite):
    # Evitar construir un escape JSON de hasta 12 bytes por carácter sin verificarlo.
    comprobar_tamano(len(valor), limite)
    tamano = 2  # Comillas.
    for caracter in valor:
        codigo = ord(caracter)
        if caracter in '\"\\\b\f\n\r\t':
            tamano += 2
        elif codigo < 32 or 127 <= codigo <= 65535:
            tamano += 6
        elif codigo > 65535:
            tamano += 12
        else:
            tamano += 1
        comprobar_tamano(tamano, limite)
    return json.dumps(valor, ensure_ascii=True)


def _fragmentos(valor, limite, nivel=0):
    if nivel > 64:
        raise FormatoInvalido("Estructura demasiado profunda.")
    tipo = type(valor)
    if valor is None:
        yield '["none",null]'
    elif tipo in (str, bool, int, float):
        if tipo is str:
            comprobar_tamano(len(valor), limite)
        if tipo is float and not math.isfinite(valor):
            raise FormatoInvalido("Se requieren números finitos.")
        etiqueta = {str: "str", bool: "bool", int: "int", float: "float"}[tipo]
        yield '["' + etiqueta + '",'
        yield _texto_json(valor, limite) if tipo is str else json.dumps(valor, allow_nan=False)
        yield ']'
    elif tipo in (datetime, date):
        yield json.dumps(["datetime" if tipo is datetime else "date", valor.isoformat()], separators=(",", ":"))
    elif tipo is list:
        yield '["list",['
        for indice, elemento in enumerate(valor):
            if indice:
                yield ','
            yield from _fragmentos(elemento, limite, nivel + 1)
        yield ']]'
    elif tipo is dict:
        yield '["dict",{'
        for indice, (clave, elemento) in enumerate(valor.items()):
            if type(clave) is not str:
                raise FormatoInvalido("Los diccionarios requieren claves de texto.")
            comprobar_tamano(len(clave), limite)
            if indice:
                yield ','
            yield _texto_json(clave, limite)
            yield ':'
            yield from _fragmentos(elemento, limite, nivel + 1)
        yield '}]'
    else:
        raise FormatoInvalido("Tipo de dato no admitido.")


def _desempacar(nodo, nivel=0):
    if nivel > 64 or type(nodo) is not list or len(nodo) != 2:
        raise ValueError
    etiqueta, valor = nodo
    tipos = {"str": str, "bool": bool, "int": int, "float": float, "none": type(None)}
    if etiqueta in tipos and type(valor) is tipos[etiqueta]:
        if etiqueta == "float" and not math.isfinite(valor):
            raise ValueError
        return valor
    if etiqueta == "date" and type(valor) is str:
        return date.fromisoformat(valor)
    if etiqueta == "datetime" and type(valor) is str:
        return datetime.fromisoformat(valor)
    if etiqueta == "list" and type(valor) is list:
        return [_desempacar(v, nivel + 1) for v in valor]
    if etiqueta == "dict" and type(valor) is dict:
        return {k: _desempacar(v, nivel + 1) for k, v in valor.items()}
    raise ValueError


def serializar(valor, max_tamano: int = MAX_TAMANO_DATO) -> bytes:
    try:
        resultado = bytearray()
        for fragmento in _fragmentos(valor, max_tamano):
            # ensure_ascii=True: cada carácter emitido representa exactamente un byte.
            comprobar_tamano(len(resultado) + len(fragmento), max_tamano)
            resultado.extend(fragmento.encode("ascii"))
        return bytes(resultado)
    except (ValueError, RecursionError, OverflowError):
        raise FormatoInvalido("No se puede serializar el dato.") from None


def deserializar(datos: bytes, max_tamano: int = MAX_TAMANO_DATO):
    comprobar_tamano(len(datos), max_tamano)
    try:
        return _desempacar(json.loads(datos))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise FormatoInvalido("Serialización inválida.") from None
