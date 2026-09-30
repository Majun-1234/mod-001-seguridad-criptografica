"""Errores públicos; sus mensajes nunca contienen datos del consumidor."""


class ErrorSeguridad(Exception):
    """Error base del módulo."""


class ClaveInvalida(ErrorSeguridad):
    """Clave ausente o con formato incorrecto."""


class DatosAlterados(ErrorSeguridad):
    """Falló la autenticación: datos, contexto o clave incorrectos."""


class FormatoInvalido(ErrorSeguridad):
    """Formato o tipo de dato no admitido."""


class VersionNoSoportada(ErrorSeguridad):
    """El formato requiere otra versión del módulo."""


class ArchivoCorrupto(DatosAlterados):
    """Archivo incompleto o no autenticado."""


class TamanoExcedido(ErrorSeguridad):
    """Dato serializado o contenedor por encima del límite configurado."""
