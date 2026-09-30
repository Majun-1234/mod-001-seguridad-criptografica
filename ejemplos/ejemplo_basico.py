"""Ejecutar con python -m ejemplos.ejemplo_basico desde el proyecto instalado."""
from pathlib import Path
from tempfile import TemporaryDirectory
from seguridad import Seguridad


def main():
    seguridad = Seguridad()
    valor = {"nombre": "Usuario", "activo": True, "saldo": 150000}
    cifrado = seguridad.cifrar(valor, contexto="usuario.perfil")
    assert cifrado.startswith("MODSEC$2$")
    assert seguridad.descifrar(cifrado, contexto="usuario.perfil") == valor
    hash_guardado = seguridad.hash_contraseña("Contraseña de demostración")
    assert seguridad.verificar_contraseña("Contraseña de demostración", hash_guardado)
    with TemporaryDirectory() as carpeta:
        origen = Path(carpeta) / "documento.txt"
        origen.write_bytes(b"Documento de demostracion")
        seguridad.cifrar_archivo(origen, Path(carpeta) / "documento.sec")
        seguridad.descifrar_archivo(Path(carpeta) / "documento.sec", Path(carpeta) / "recuperado.txt")
        assert origen.read_bytes() == (Path(carpeta) / "recuperado.txt").read_bytes()
    print("Contraseñas, datos y archivos v2: demostración completada.")


if __name__ == "__main__":
    main()
