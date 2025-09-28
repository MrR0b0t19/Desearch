# Desearch

Mapeo rápido y práctico para identificar superficies de deserialización insegura, inyección de objetos, PHAR, configuraciones peligrosas de JSON/XML y puntos de entrada a cadenas de gadgets, con salida directa y legible en terminal usando `rich`.

La herramienta está pensada para **caja blanca** (búsqueda directa en archivos de un repositorio) y **caja gris** (sondeo HTTP con cargas canario no destructivas). El objetivo es que personas con **poco entendimiento previo** puedan comprender y ubicar al instante indicadores clave para priorizar la revisión manual y, cuando proceda, preparar pruebas de explotación controladas.

**Motivación:** facilitar la comprensión y la identificación inmediata de riesgos de deserialización y uso de gadgets para investigación defensiva, detección y reporte responsable, **por un mundo más seguro**.

---

## Características

* **Fingerprint de formatos** en archivos o blobs:

  * PHP `serialize`
  * Python Pickle (v0, v1–v5)
  * JSON con discriminadores de tipo (`$type`, `@class`, `@type`) y JSONPickle
  * YAML (incl. etiquetas personalizadas)
  * XML con DOCTYPE/ENTITY (riesgo XXE), estilos de DataContract/NetDataContract de .NET
  * Java Serialization (AC ED 00 05)
  * .NET BinaryFormatter (cabecera típica)
  * Ruby Marshal
  * Soporte para **Base64 anidado** (decodifica y vuelve a detectar)

* **Sondeo HTTP “canario”** (GET/POST):

  * Envía cargas inocuas para revelar parseos peligrosos (serialize PHP Base64, Pickle pequeño, JSON con discriminador, YAML, XML básico y con DOCTYPE).
  * Reporta código de estado, reflejo del payload y pistas de mensajes.

* **Caja blanca PHP:**

  * Localiza `serialize`/`unserialize`.
  * Señala sinks de I/O de archivos (`file_exists`, `file_get_contents`, `fopen`, etc.) para **cadena PHAR**.
  * Marca archivos con `__wakeup`/`__destruct`/`__toString` junto a **sinks peligrosos** (`exec`, `include`, etc.) como candidatos a **gadgets**.
  * Detecta patrones **Laravel Import/Export** (`serialize + base64_encode` ↔ `unserialize + base64_decode`).
  * Identifica uso de Blade sin escape `{!! ... !!}` como indicador de XSS reflejado en flujos de importación.

* **Caja blanca Python:**

  * `pickle.loads`, `pickle.Unpickler`, `jsonpickle.decode`.
  * `yaml.load` sin `safe_load`.
  * Parsers XML (`fromstring`, `parseString`) como indicadores de riesgo si no se endurece.
  * Pistas de “puentes” a serializadores .NET en código Python.

* **Caja blanca genérica (JSON/XML):**

  * Banderas peligrosas típicas:

    * Jackson: `enableDefaultTyping`, `@JsonTypeInfo`
    * Json.NET: `TypeNameHandling` distinto de `None`
    * XML: `XmlResolver = ...`

* **Sugerencias de búsqueda y gadget hunting:**

  * Imprime consejos y queries breves para guiar investigación adicional y búsqueda de cadenas conocidas.

* **Salida en terminal con `rich`:**

  * Tablas y paneles legibles, sin generar archivos JSON.

---

## Instalación

Requisitos mínimos: Python 3.8+

```bash
pip install rich requests
```

Clona el repositorio y coloca el script en la raíz del proyecto o en tu `$PATH`.

---

## Uso rápido

Fingerprint de un archivo (binario o texto):

```bash
python search.py sample.bin
```

Si el contenido está en Base64:

```bash
python search.py dump.b64 --as-base64
```

Sondeo HTTP con cargas canario:

```bash
python search.py --url http://host/settings --param settings --method POST --extra "import=1"
```

Caja blanca:

```bash
# PHP: sinks PHAR, gadgets, serialize/unserialize, Blade sin escape
python search.py --scan-php /ruta/al/proyecto

# Python: pickle, yaml.load inseguro, jsonpickle, parsers XML
python search.py --scan-py /ruta/al/proyecto

# Genérico: Jackson/Json.NET/XmlResolver en .java/.cs/.xml/.json
python search.py --scan-generic /ruta/al/proyecto
```

---

## Qué detecta y por qué importa

### PHP

* `unserialize` inseguro y pareja Laravel Import/Export: superficies de **Object Injection**.
* Sinks de I/O controlables por usuario con uploads: base para **PHAR deserialization** vía `phar://` y metadatos.
* `__wakeup`/`__destruct` junto a `exec/include/...`: candidatos a **gadgets** de RCE.
* Blade `{!! ... !!}` en mensajes tras importar datos: puede encadenar **XSS reflejado**.

### Python

* `pickle.loads` y `Unpickler` con datos no confiables: ejecución de `__reduce__/__reduce_ex__`.
* `yaml.load` sin `safe_load`: instanciación de tipos arbitrarios si el loader lo permite.
* `jsonpickle.decode`: reconstrucción de objetos basada en metadata.
* Parsers XML sin endurecer: riesgo de XXE si se aceptan DTD/entidades externas.

### JSON

* Json.NET con `TypeNameHandling` habilitado e inadecuado: inyección de tipos y “setter gadgets” en .NET.
* Jackson con `enableDefaultTyping` o `@JsonTypeInfo`: deserialización de tipos arbitrarios y cadenas de gadgets.

### XML

* DOCTYPE/ENTITY: XXE/SSRF si no se deshabilitan entidades externas.
* `XmlResolver` habilitado: potencial de resolución de entidades externas.

### Java / .NET / Ruby

* Java Serialization (AC ED 00 05), .NET BinaryFormatter y Ruby Marshal: formatos con historial de gadgets y RCE si se deserializa input no confiable.

---

## Flujo de trabajo recomendado

1. **Fingerprint** de artefactos o respuestas sospechosas para saber “qué es” antes de tocar nada.
2. **Caja blanca**:

   * PHP: buscar `unserialize`, sinks de I/O y métodos mágicos con sinks.
   * Python: localizar `pickle.loads`, `yaml.load`, `jsonpickle.decode`, parsers XML.
   * Genérico: configuraciones peligrosas en JSON/XML.
3. **Sondeo HTTP canario** en endpoints con semántica de importación/expansión/plantillas.
4. Usar las **sugerencias y queries** impresas para investigar gadgets conocidos o configuraciones explotables en el stack objetivo.
5. Preparar **POCs locales controlados** y pruebas con autorización.

---

## Ejemplos de uso típico

* **Laravel Import/Export** con `serialize/base64_encode` ↔ `unserialize/base64_decode`: marcar archivo del controlador y vista donde se imprime el nombre sin escapar. Probar actualización de campos y, si procede, XSS en mensajes.
* **PHAR**: si hay uploads y un endpoint que llama `file_exists($request->query('_'))`, probar `phar://uploads/<hash>.jpg` tras subir un `.phar` camuflado como `.jpg`.
* **Json.NET**: si se detecta `TypeNameHandling` distinto de `None`, buscar endpoints JSON y considerar payloads con `$type`.
* **Jackson**: si aparece `enableDefaultTyping` o `@JsonTypeInfo`, considerar `@class` con gadgets conocidos.

---

## Interpretación de la salida

* Cada archivo con hallazgos aparece como **tabla** con:

  * Tipo de indicador (p. ej. Insecure Unserialize, PHAR FileIO UserInput, Magic Gadget).
  * Línea aproximada.
  * Snippet corto.
* El fingerprint muestra la lista de **señales por formato** y una sección de **sugerencias** y **consultas** para acelerar la búsqueda.

---

## Documentos de referencia incluidos

Colocados en la carpeta de referencias del proyecto (nombres representativos):

* `us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf`
* `BH_US_12_Forshaw_Are_You_My_Type_WP.pdf`
* `us-18-Haken-Automated-Discovery-of-Deserialization-Gadget-Chains-wp.pdf`
* `us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf`

Estos trabajos fundamentan el enfoque sobre discriminadores de tipo en JSON, riesgos de serializadores .NET/Java, descubrimiento automatizado de gadgets y vectores prácticos de PHP, incluyendo PHAR.

---

## Limitaciones

* El análisis es **estático y heurístico**: falsos positivos/negativos son posibles.
* No ejecuta deserialización ni carga código. Las pruebas activas deben realizarse en entornos controlados y con autorización.
* La detección de gadgets en PHP se basa en co-ocurrencia de métodos mágicos y sinks; un análisis de flujo completo requeriría herramientas de AST/CFG.

---

## Contribuir

* Abre issues con:

  * Nuevos indicadores de formatos o librerías.
  * Reglas específicas por framework (Laravel, Symfony, Django, Spring, ASP.NET).
  * Ejemplos de salidas y mejoras de usabilidad en terminal.
* Pull requests con:

  * Nuevas firmas y mejoras de detección.
  * Integración opcional de parseo de AST para PHP/Python.
  * Perfiles de explotación segura para laboratorio (POCs no destructivas).

---

## Consideraciones de seguridad y uso responsable

Utiliza esta herramienta exclusivamente con permiso y para fines educativos, de auditoría interna y defensa. No está diseñada para causar daño, sino para **detectar y mitigar**. Verifica siempre en entornos controlados y reporta de manera responsable. La intención del proyecto es contribuir a la comprensión y mejora de la seguridad, **por un mundo más seguro**.

---
