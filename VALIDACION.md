# Validación de la segunda iteración

Fecha: 30 de septiembre de 2026. Versión: 1.0.0 estable.

## Cambios

Modificados: claves.py, formato.py, cifrado.py, archivos.py, serializacion.py,
seguridad.py, errores.py, __init__.py, pyproject.toml, MANIFEST.in, .env.example,
README.md, ejemplo_basico.py, test_cifrado.py y test_archivos.py.
Las pruebas de contraseñas originales se conservaron sin cambios.
`.gitignore` fue revisado y conserva las exclusiones solicitadas sin modificaciones.

Nuevos: derivacion.py, limites.py, test_derivacion.py, test_rotacion.py,
test_limites.py, test_compatibilidad.py, fixtures/datos_v1.json,
fixtures/archivo_v1.bin y este informe.

## Decisiones

- HKDF-SHA256 mantenida por cryptography, con dominios distintos para datos y
  archivos y parámetros fijos del formato v2. No hay implementación manual de KDF.
- key_id autenticado y resolución explícita de la maestra por ID.
- Escritura exclusivamente v2; lectura v1 usando la maestra histórica sin HKDF.
- Proveedores antiguos sin IDs continúan asociados a KEY01.
- Límite inclusivo predeterminado de 10 MiB de JSON serializado, independiente de
  streaming. Validación previa de longitudes de contenedor/Base64 y análisis JSON.
- La clave pública de las muestras v1 es bytes(range(32)): sirve únicamente para
  pruebas reproducibles. Las muestras fueron generadas ejecutando el paquete
  anterior instalado 1.0.0 en modo aislado, no el nuevo lector.

## Límites de la revisión

Sin recifrado masivo, rotación automática ni proveedores cloud. La aplicación
debe conservar maestras históricas, evitar reutilizar IDs y mantener respaldos.
El tamaño configurado no es un límite total de RAM. Se mantienen las limitaciones
de enlaces duros, temporales en texto claro y ausencia de borrado seguro de memoria.
La versión 1.0.0 fue aprobada tras la revisión independiente posterior de la implementación.

## Resultados ejecutados

- Suite completa: **107 pruebas** (59 existentes conservadas y 48 nuevas).
  Comando: `.venv\Scripts\python.exe -m pytest -q`.
  Resultado exacto: **107 passed in 1.06s**.
- Ejemplo: **Contraseñas, datos y archivos v2: demostración completada.**
- Construcción con `python -m build --no-isolation`: sdist y wheel generados
  correctamente para 1.0.0.
- Instalación local del wheel 1.0.0: correcta. Prueba con Python `-I`, sin
  importar el código del directorio de trabajo: rotación y archivos correctos.
- `pip check`: **No broken requirements found.**
- Distribuciones inspeccionadas: sin .venv, cachés, build, dist ni .env real;
  el sdist incluye pruebas, conftest y muestras históricas. El wheel contiene
  únicamente seguridad/ y los metadatos propios de la distribución.
- Revisión de archivos: no se generaron secretos reales persistentes. La única
  maestra fija es la pública de las muestras de prueba, identificada explícitamente.

Entorno de validación: Windows, Python 3.12; argon2-cffi 25.1.0, PyNaCl 1.6.2,
cryptography 48.0.1, pytest 9.1.1. No se ejecutó esta suite en Linux/macOS ni en
otras versiones de Python. Los artefactos anteriores del desarrollador se conservan
en dist/ y se distinguen por la versión; usa los que terminan en 1.0.0.
