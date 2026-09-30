from .errores import FormatoInvalido, TamanoExcedido

MAX_TAMANO_DATO = 10 * 1024 * 1024


def validar_limite(limite: int) -> int:
    if type(limite) is not int or limite <= 0:
        raise FormatoInvalido("El límite debe ser un entero positivo de bytes.")
    return limite


def comprobar_tamano(tamano: int, limite: int):
    if tamano > limite:
        raise TamanoExcedido("El dato supera el límite configurado.")
