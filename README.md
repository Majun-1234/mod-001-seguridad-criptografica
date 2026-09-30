# MOD-001 · Seguridad criptográfica

Módulo independiente de la colección **Modulos** para contraseñas, datos
recuperables y archivos. Esta segunda iteración es **1.0.0rc2**, candidata a v1.0
estable, pendiente de revisión posterior. La versión del formato cifrado es **2**;
no debe confundirse con la versión del paquete. No se reconstruyó el módulo.

## Requisitos e instalación

Python 3.11 o superior. Dependencias: argon2-cffi, PyNaCl (libsodium) y cryptography.
La última se usa exclusivamente para HKDF; PyNaCl 1.6.2 no expone `crypto_kdf`.

Desde esta carpeta, en PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[test]"
```

Si Python no está en PATH, usa `py -3` o la ruta de tu ejecutable. En este equipo
ya existe `.venv` con las dependencias. En Linux/macOS usa `.venv/bin/python`.

## Una sola clave

La configuración anterior sigue funcionando: `MODSEC_CLAVE` contiene una maestra
aleatoria de 32 bytes en Base64. Se identifica como `KEY01` para escritura v2.

```powershell
$env:MODSEC_CLAVE = & .\.venv\Scripts\python.exe -c "from seguridad import generar_clave; print(generar_clave())"
.\.venv\Scripts\python.exe -m ejemplos.ejemplo_basico
```

Esta clave de demostración sólo vive en el entorno de la sesión. Para datos
persistentes, conserva la misma clave en un gestor de secretos externo. Generar
otra clave no permite recuperar datos anteriores. Base64 representa la clave,
pero no la protege. No se creó ningún `.env` con secretos reales.

`.env.example` es una plantilla. La aplicación consumidora puede cargar `.env`
para desarrollo; el módulo no lo carga ni instala un cargador automáticamente.

## Arquitectura: maestra y subclaves

Cada generación de clave tiene **una maestra** administrada externamente. No se
configuran claves separadas para cada operación. Internamente se derivan:

- Subclave de datos: HKDF-SHA256 con `info=b"MODSEC/v2/datos"`.
- Subclave de archivos: HKDF-SHA256 con `info=b"MODSEC/v2/archivos"`.

Se usa HKDF de cryptography, longitud 32 bytes y salt público fijo
`b"MODSEC/v2/HKDF-SHA256"`. Estos parámetros son parte inmutable del formato v2.
La clave maestra debe tener alta entropía: HKDF no convierte una contraseña humana
sin entropía en una clave segura. Las contraseñas de usuarios usan Argon2id.

Una misma maestra produce las mismas subclaves, pero cada dominio produce una
subclave distinta. Los consumidores no deben derivarlas ni almacenarlas.
No se implementaron primitivas ni una KDF manual; se verificaron la API instalada
48.0.1 de cryptography y las API existentes de PyNaCl.

## Identificadores y varias generaciones de claves

`key_id` es un nombre lógico público, no un secreto, huella ni contraseña.
Se permiten entre 1 y 64 caracteres ASCII: letras, números, guion y guion bajo.
No reutilices un ID para una maestra diferente si todavía existen datos con ese ID.

Configuración de varias generaciones, con valores obtenidos de tu gestor externo:

```text
MODSEC_CLAVE_ACTIVA=KEY02
MODSEC_CLAVE_KEY01=<Base64 de la maestra histórica>
MODSEC_CLAVE_KEY02=<Base64 de la nueva maestra>
```

Los textos entre ángulos son marcadores, no claves para copiar. Para una prueba
local sin guardar secretos en archivos:

```powershell
$env:MODSEC_CLAVE_KEY01 = & .\.venv\Scripts\python.exe -c "from seguridad import generar_clave; print(generar_clave())"
$env:MODSEC_CLAVE_KEY02 = & .\.venv\Scripts\python.exe -c "from seguridad import generar_clave; print(generar_clave())"
$env:MODSEC_CLAVE_ACTIVA = "KEY01"
# Tras cifrar algunos datos con KEY01, cambiar únicamente el selector:
$env:MODSEC_CLAVE_ACTIVA = "KEY02"
```

La maestra de KEY01 en una migración real debe ser la original; no generes otra.
Las nuevas escrituras usan KEY02. Al leer un dato o archivo anterior v2, el módulo
lee su ID y consulta KEY01, aunque la activa sea KEY02. Mantén ambas maestras hasta
recifrar y verificar todos los datos y respaldos antiguos. **Eliminar KEY01 hará
imposible descifrar datos y archivos que todavía dependan de KEY01.**

Por defecto la activa es KEY01. `MODSEC_CLAVE_KEY01` tiene prioridad sobre
`MODSEC_CLAVE` al resolver KEY01 en v2. Para evitar confusión, utiliza una única
convención por entorno, o asegúrate de que ambas contienen la misma maestra.
Una variable presente pero vacía es inválida: no provoca una búsqueda alternativa.
Un ID desconocido se rechaza; no se prueban todas las maestras.

## API y proveedores

```python
from datetime import date
from seguridad import Seguridad, TamanoExcedido

seguridad = Seguridad(max_tamano_dato=10 * 1024 * 1024)
hash_guardado = seguridad.hash_contraseña("MiClave123")
assert seguridad.verificar_contraseña("MiClave123", hash_guardado)
if seguridad.necesita_actualizacion(hash_guardado):
    # Actualizar en la base de datos después de autenticar correctamente.
    hash_guardado = seguridad.hash_contraseña("MiClave123")

valor = {"nombre": "Usuario", "activo": True, "fecha": date(2026, 9, 30)}
cifrado = seguridad.cifrar(valor, contexto="usuario.perfil")
assert seguridad.descifrar(cifrado, contexto="usuario.perfil") == valor

seguridad.cifrar_archivo("contrato.pdf", "contrato.pdf.sec", contexto="contrato")
seguridad.descifrar_archivo("contrato.pdf.sec", "recuperado.pdf", contexto="contrato")
```

El contexto debe coincidir exactamente. Puedes incorporar un registro o usuario,
por ejemplo `proyecto:usuario:123:email`. No se almacena en el contenedor y no
necesita ser secreto. El ID, algoritmo y versión forman parte de la AAD autenticada.

`GestorClaves` define `obtener_id_clave_activa() -> str` y
`obtener_clave(key_id: str | None = None) -> bytes`. La fachada obtiene el ID activo
y después resuelve esa misma clave, evitando consultar dos veces el selector.
Para otro entorno:

```python
from seguridad import Seguridad, GestorClavesEntorno
seguridad = Seguridad(GestorClavesEntorno("MI_CLAVE", id_legacy="KEY01"))
# Usa MI_CLAVE_ACTIVA, MI_CLAVE_KEY01, etc.
```

Un proveedor personalizado moderno implementa ambos métodos. Sus errores y
representaciones deben proteger secretos. Los proveedores antiguos que sólo
implementan `obtener_clave()` siguen funcionando y se asocian a KEY01, sin rotación
por ID. La presencia de `obtener_id_clave_activa` identifica el contrato moderno.

## Compatibilidad v1 y v2

Todas las escrituras nuevas de datos y archivos usan v2 con ID y subclaves.
Los lectores también admiten v1, usando directamente la maestra histórica, como
hacía la versión anterior. No se intenta v1 si falla la autenticación de v2.

Como v1 no tenía ID, `GestorClavesEntorno.obtener_clave_legacy()` utiliza
`MODSEC_CLAVE` si está presente; en su ausencia resuelve el `id_legacy` configurado
(por defecto KEY01). **La activa nunca determina la clave histórica de v1.**
Para migrar a varias claves, mueve la maestra original a `MODSEC_CLAVE_KEY01`,
retira la variable antigua y conserva KEY01. Si había varios orígenes v1 con
maestras distintas, debes seleccionar su proveedor externamente: sus contenedores
no permiten identificar automáticamente la maestra.

En proveedores modernos sin `obtener_clave_legacy()`, v1 se asocia a KEY01.
Puedes implementar ese método opcional para una asociación histórica distinta.
La suite contiene muestras reales producidas por el paquete anterior 1.0.0,
con una **clave pública exclusivamente de prueba**, nunca de producción.

Formatos:

- Datos v1: `MODSEC$1$XCHACHA20$Base64(nonce+ciphertext)`.
- Datos v2: `MODSEC$2$KEY01$XCHACHA20$Base64(nonce+ciphertext)`.
  El tipo está dentro del JSON etiquetado autenticado y cifrado.
- Archivo v1: `MODSECFILE\0`, versión binaria 1, `SECRETSTREAM\0`, cabecera
  libsodium de 24 bytes y registros.
- Archivo v2: mismo prefijo con versión binaria 2 y, después del algoritmo,
  un byte con longitud del ID seguido del ID ASCII; luego cabecera libsodium
  y registros. Toda la cabecera de formato se autentica como AAD.

Los registros contienen longitud uint32 big-endian y ciphertext SecretStream.
Cada bloque usa TAG_MESSAGE; el cierre es un registro vacío TAG_FINAL.
Se rechazan alteraciones, reordenamientos, truncamiento y bytes después del final.
Versiones desconocidas se rechazan explícitamente.

## Límites y tipos

`max_tamano_dato` vale por defecto **10 MiB (10 * 1024 * 1024 bytes)**. Debe ser un
entero positivo. Limita el JSON etiquetado serializado en UTF-8, no el tamaño del
objeto Python ni la longitud del string original. El límite exacto es inclusivo.
JSON escapa Unicode, por lo que caracteres Unicode pueden ocupar varios bytes.
La serialización acumula fragmentos con controles de tamaño, sin copiar primero
una estructura etiquetada completa. Los escapes excesivos se rechazan antes de
construirlos. `TamanoExcedido` indica que se superó el límite.

Al leer, se limita el contenedor antes de dividirlo, se comprueba la longitud
Base64 antes de decodificar y se verifica el tamaño decodificado antes de descifrar
y analizar JSON. Se permiten 40 bytes adicionales (nonce de 24 + tag de 16) y la
expansión Base64 correspondiente. Los contextos de datos también están limitados
al tamaño configurado. El consumo total de RAM puede ser varias veces ese límite
por Base64, objetos JSON y copias de la biblioteca; no es una cuota total de RAM.

**El límite de datos no limita el tamaño de los archivos:** siguen usando bloques
de 1 MiB. Los contextos de archivos tienen un límite independiente de 10 MiB.

Tipos: str, int, float finito, bool, None, listas, diccionarios con claves str,
date y datetime, anidados hasta profundidad 64. No se usa pickle, eval ni exec.
No se admiten bytes, tuplas, objetos personalizados, ciclos, NaN ni infinito.
Los enteros están sujetos también a los límites JSON de Python. datetime conserva
hora y desplazamiento UTC, pero no el nombre de zona ni `fold`.

## Seguridad y errores

Argon2id y salts automáticos de argon2-cffi para contraseñas; estas operaciones
no requieren maestra. Contraseña incorrecta devuelve False, hash inválido produce
FormatoInvalido. Verifica los hashes guardados bajo control de la aplicación;
sus parámetros afectan recursos. Ajusta concurrencia y tasa en el consumidor.

XChaCha20-Poly1305 de libsodium usa un nonce aleatorio de 24 bytes por dato.
Los archivos usan SecretStream. Ningún error de autenticación distingue clave,
contexto o contenido incorrectos. No se registran secretos.

Los destinos deben ser nuevos. Se escribe un temporal y se publica sólo tras
completar la operación, mediante enlace duro sin sobrescritura. Se requiere soporte
de enlaces duros (NTFS/ext4, por ejemplo). El temporal de descifrado contiene
texto claro: usa un directorio privado y permisos adecuados. Los fallos normales
eliminan el temporal; un cierre abrupto puede dejar `.modsec-*`. No se garantiza
borrado forense ni limpieza segura de claves en memoria Python.

Errores públicos: ErrorSeguridad, ClaveInvalida, DatosAlterados, FormatoInvalido,
VersionNoSoportada, ArchivoCorrupto y TamanoExcedido. Fallos de E/S se convierten en
ErrorSeguridad. No registres contraseñas, claves ni entradas sensibles.

No hay rotación automática, recifrado masivo ni proveedores cloud. El cifrado no
oculta tamaños ni impide replay de datos válidos antiguos; el consumidor debe
manejar ese estado. Conserva respaldos seguros de claves y datos. Queda pendiente
una revisión independiente de los cambios antes de declarar la versión estable.

## Pruebas, ejemplo e integración

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ejemplos.ejemplo_basico
.\.venv\Scripts\python.exe -m pip install build
.\.venv\Scripts\python.exe -m build
```

La suite cubre las funciones originales, HKDF, separación de dominios, rotación
KEY01 a KEY02, AAD del ID, límites, compatibilidad con muestras v1 y streaming.
Consulta `VALIDACION.md` para el resultado de esta iteración.

Para instalar en otro proyecto:

```powershell
python -m pip install "C:\Users\matia\OneDrive\Escritorio\Nueva-Carpeta\Proyectos\Modulos\mod-001-seguridad-criptografica"
# Alternativa: instalar el wheel concreto generado en dist/.
python -m pip install "ruta\mod_001_seguridad_criptografica-1.0.0rc2-py3-none-any.whl"
```

Importa `from seguridad import Seguridad`; evita otro paquete con el mismo nombre
de importación. También puedes copiar `seguridad/` declarando las tres dependencias.
`.venv/`, cachés, build/, dist/ y *.egg-info/ se ignoran en Git y no se incluyen
en la distribución. Las muestras de compatibilidad se incluyen sólo en el sdist,
junto con pruebas, documentación y ejemplo. El wheel contiene el módulo y metadatos.

Referencias verificadas:
[Argon2](https://argon2-cffi.readthedocs.io/en/stable/api.html),
[PyNaCl SecretStream](https://github.com/pyca/pynacl/blob/main/src/nacl/bindings/crypto_secretstream.py),
[HKDF de cryptography](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/).

