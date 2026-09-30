from . import archivos, cifrado
from .claves import GestorClaves, GestorClavesEntorno, validar_clave, validar_key_id
from .contrasenas import Contrasenas
from .errores import ClaveInvalida
from .limites import MAX_TAMANO_DATO, validar_limite


class Seguridad:
    """Fachada; la clave se consulta solamente al cifrar o descifrar."""

    def __init__(self, gestor_claves: GestorClaves | None = None, *, max_tamano_dato: int = MAX_TAMANO_DATO):
        self._gestor = gestor_claves if gestor_claves is not None else GestorClavesEntorno()
        self._contrasenas = Contrasenas()
        self.max_tamano_dato = validar_limite(max_tamano_dato)

    def _id_activo(self):
        if hasattr(self._gestor, "obtener_id_clave_activa"):
            return validar_key_id(self._gestor.obtener_id_clave_activa())
        return "KEY01"  # Adaptación de proveedores v1 sin identificadores.

    def _resolver(self, version, key_id):
        if version == 1 and hasattr(self._gestor, "obtener_clave_legacy"):
            clave = self._gestor.obtener_clave_legacy()
        elif hasattr(self._gestor, "obtener_id_clave_activa"):
            clave = self._gestor.obtener_clave("KEY01" if version == 1 else key_id)
        else:
            if key_id not in (None, "KEY01"):
                raise ClaveInvalida("El proveedor histórico sólo resuelve KEY01.")
            clave = self._gestor.obtener_clave()
        return validar_clave(clave)

    def hash_contraseña(self, contraseña: str) -> str:
        return self._contrasenas.hash_contraseña(contraseña)

    def verificar_contraseña(self, contraseña: str, hash_guardado: str) -> bool:
        return self._contrasenas.verificar_contraseña(contraseña, hash_guardado)

    def necesita_actualizacion(self, hash_guardado: str) -> bool:
        return self._contrasenas.necesita_actualizacion(hash_guardado)

    def cifrar(self, valor, contexto: str = "") -> str:
        key_id = self._id_activo()
        return cifrado.cifrar(valor, self._resolver(2, key_id), contexto, key_id=key_id, max_tamano=self.max_tamano_dato)

    def descifrar(self, texto: str, contexto: str = ""):
        return cifrado.descifrar(texto, self._resolver, contexto, max_tamano=self.max_tamano_dato)

    def cifrar_archivo(self, entrada, salida, contexto: str = ""):
        key_id = self._id_activo()
        archivos.cifrar_archivo(entrada, salida, self._resolver(2, key_id), contexto, key_id=key_id)

    def descifrar_archivo(self, entrada, salida, contexto: str = ""):
        archivos.descifrar_archivo(entrada, salida, self._resolver, contexto)

    def __repr__(self):
        return "Seguridad(<configuración oculta>)"
