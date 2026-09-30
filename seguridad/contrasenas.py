from argon2 import PasswordHasher, Type
from argon2.exceptions import HashingError, InvalidHashError, VerificationError, VerifyMismatchError

from .errores import FormatoInvalido


class Contrasenas:
    def __init__(self):
        self._hasher = PasswordHasher(type=Type.ID)

    def hash_contraseña(self, contraseña: str) -> str:
        if type(contraseña) is not str:
            raise FormatoInvalido("La contraseña debe ser texto.")
        try:
            return self._hasher.hash(contraseña)
        except (UnicodeError, HashingError):
            raise FormatoInvalido("No se pudo procesar la contraseña.") from None

    def verificar_contraseña(self, contraseña: str, hash_guardado: str) -> bool:
        if type(contraseña) is not str or type(hash_guardado) is not str:
            raise FormatoInvalido("La contraseña y el hash deben ser texto.")
        try:
            return self._hasher.verify(hash_guardado, contraseña)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError, UnicodeError):
            raise FormatoInvalido("Hash de contraseña inválido.") from None

    def necesita_actualizacion(self, hash_guardado: str) -> bool:
        if type(hash_guardado) is not str:
            raise FormatoInvalido("El hash debe ser texto.")
        try:
            return self._hasher.check_needs_rehash(hash_guardado)
        except (InvalidHashError, ValueError, UnicodeError):
            raise FormatoInvalido("Hash de contraseña inválido.") from None
