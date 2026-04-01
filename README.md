# Scan-IA-Models
escaner de Seguridad para  modelos de IA 

# 🔐 Scanner Autónomo de Modelos IA

**Versión:** 5.0  
**Herramientas:** Fickling + ModelScan + SHA256  
**Entorno:** Sector Bancario — Validación de seguridad pre-producción

---

## 📋 Tabla de Contenidos

1. [¿Qué es y para qué sirve?](#qué-es-y-para-qué-sirve)
2. [¿Qué amenazas detecta?](#qué-amenazas-detecta)
3. [Requisitos](#requisitos)
4. [Instalación](#instalación)
5. [Uso](#uso)
6. [Formato del archivo de lista](#formato-del-archivo-de-lista)
7. [¿Qué analiza y cómo?](#qué-analiza-y-cómo)
8. [Pruebas que realiza](#pruebas-que-realiza)
9. [Interpretación de resultados](#interpretación-de-resultados)
10. [Reportes generados](#reportes-generados)
11. [Directorios ignorados](#directorios-ignorados)
12. [Falsos positivos — qué filtra](#falsos-positivos--qué-filtra)
13. [Limitaciones](#limitaciones)
14. [Recomendaciones para el banco](#recomendaciones-para-el-banco)

---

## ¿Qué es y para qué sirve?

Este script valida la seguridad de modelos de Inteligencia Artificial (LLMs, modelos de embeddings, traducción, etc.) **antes de que sean desplegados en producción** dentro de un entorno bancario.

Los modelos de IA descargados desde repositorios externos (HuggingFace, Nexus proxy, etc.) pueden contener código malicioso embebido en sus archivos de pesos. Este scanner detecta esas amenazas de forma automática y genera un reporte trazable para el equipo de seguridad.

### Problema que resuelve

Los archivos de modelo en formato **Pickle** (`.bin`, `.pkl`) son internamente scripts Python serializados. Esto significa que al cargarse en memoria pueden **ejecutar código arbitrario** sin que el usuario lo sepa. Un modelo aparentemente normal puede contener un backdoor, un comando de red, o instrucciones para comprometer el servidor.

```
Modelo descargado → Cargado con torch.load() → EJECUCIÓN DE CÓDIGO MALICIOSO
```

Este scanner inspecciona el interior de esos archivos **sin cargarlos**, identificando patrones peligrosos de forma segura.

---

## ¿Qué amenazas detecta?

| Keyword peligrosa | Tipo de ataque | Riesgo en banca |
|---|---|---|
| `__reduce__` | RCE via Pickle | Compromiso total del servidor al cargar el modelo |
| `exec` | Ejecución de código | Ejecuta código Python arbitrario en producción |
| `eval` | Evaluación dinámica | Inyección y ejecución de instrucciones externas |
| `os.system` | Comando del SO | Ejecuta comandos del sistema operativo del servidor |
| `subprocess` | Proceso del sistema | Lanza procesos — escalada de privilegios |
| `GLOBAL` | Importación arbitraria | Carga librerías maliciosas no controladas |
| `builtins.open` | Acceso al filesystem | Lee/escribe archivos sensibles del servidor |
| `importlib` | Importación dinámica | Carga código externo post-despliegue |
| `pty` | Terminal del sistema | Shell reversa hacia el atacante |
| `socket` | Conexión de red | Exfiltración de datos bancarios |
| `shutil.rmtree` | Destrucción de archivos | Elimina datos en producción |
| `newobj` | Instancia de clases | Crea objetos arbitrarios en memoria |

---

## Requisitos

### Python
- Python 3.8 o superior

### Librerías externas (deben instalarse desde Nexus)
```
fickling>=0.0.7
modelscan>=0.5.0
```

### Librerías estándar utilizadas (no requieren instalación)
```
zipfile, os, sys, glob, subprocess, shutil, hashlib, json, datetime
```

---

## Instalación

### Desde Nexus (entorno bancario)

```bash
# Activar entorno virtual
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Instalar desde Nexus PyPI proxy
pip install fickling modelscan \
  --index-url https://USUARIO:PASSWORD@banco-central-de-chile.repo.sonatype.app/repository/pypi-proxy/simple/ \
  --trusted-host banco-central-de-chile.repo.sonatype.app
```

### Usando variables de entorno (recomendado — no expone credenciales)

```bash
export NEXUS_USER="tu_usuario"
export NEXUS_PASS="tu_password"

pip install fickling modelscan \
  --index-url https://${NEXUS_USER}:${NEXUS_PASS}@banco-central-de-chile.repo.sonatype.app/repository/pypi-proxy/simple/ \
  --trusted-host banco-central-de-chile.repo.sonatype.app
```

### Configuración permanente en pip.conf

```ini
# Linux/Mac: ~/.config/pip/pip.conf
# Windows:   %APPDATA%\pip\pip.ini

[global]
index-url = https://USUARIO:PASSWORD@banco-central-de-chile.repo.sonatype.app/repository/pypi-proxy/simple/
trusted-host = banco-central-de-chile.repo.sonatype.app
```

### Verificar instalación

```bash
fickling --version
modelscan --version
```

---

## Uso

### Modo 1 — Escanear una ruta específica

```bash
python3 scan_models.py ./jinaai/jina-embeddings-v3
```

Escanea recursivamente todos los archivos de modelo dentro de esa ruta.

### Modo 2 — Escanear directorio completo

```bash
python3 scan_models.py /home/juanito/validar/modelos
```

Descubre y escanea todos los archivos `.bin`, `.h5`, `.pkl` y `.safetensors` en el directorio y sus subdirectorios.

### Modo 3 — Escanear lista desde archivo

```bash
python3 scan_models.py -file modelos.txt
```

Lee una lista de rutas desde un archivo de texto y escanea cada una.

### Modo 4 — Sin argumentos (mostrar ayuda)

```bash
python3 scan_models.py
```

### Ejemplos completos

```bash
# Un modelo específico
python3 scan_models.py ./Qwen/Qwen3-30B-A3B

# Todos los modelos del directorio de trabajo actual
python3 scan_models.py .

# Lista de modelos a validar antes del deploy
python3 scan_models.py -file lista_modelos_produccion.txt

# Ruta absoluta
python3 scan_models.py /data/ai-models/llama3
```

---

## Formato del archivo de lista

Cuando se usa `-file`, el archivo debe tener **una ruta por línea**.  
Las líneas que comienzan con `#` son comentarios y se ignoran.  
Las líneas vacías también se ignoran.

**Ejemplo `modelos.txt`:**

```
# ── Modelos de embeddings ──
./jinaai/jina-embeddings-v3
./jinaai/jina-embeddings-v4
./sentence-transformers/all-MiniLM-L6-v2
./sentence-transformers/all-MiniLM-L12-v2
./intfloat/multilingual-e5-base

# ── Modelos de traducción ──
./Helsinki-NLP/opus-mt-en-es
./Helsinki-NLP/opus-mt-es-en

# ── LLMs ──
./meta-llama/Llama-3.2-1B-Instruct
./Qwen/Qwen3-30B-A3B

# ── Modelo de indexación ──
./llamaindex/vdr-2b-multi-v1
```

---

## ¿Qué analiza y cómo?

El script descubre automáticamente todos los archivos de modelo en la ruta indicada y aplica la herramienta correcta según el tipo de archivo:

```
Archivo encontrado
       │
       ├── .safetensors ──→ ModelScan directo
       │                    (formato seguro, no ejecuta código)
       │
       ├── .bin ───────────→ Fickling (intenta abrir como ZIP PyTorch)
       │                         │
       │                         ├── Es ZIP → extrae data.pkl → Fickling analiza
       │                         └── No ZIP → fallback a ModelScan
       │
       ├── .pkl ───────────→ Fickling directo sobre el archivo
       │
       └── .h5 ────────────→ ModelScan directo
                             (formato Keras/TensorFlow)
```

### Por cada archivo también calcula:
- **Hash SHA256** para trazabilidad y detección de modificaciones

---

## Pruebas que realiza

### 1. Análisis de deserialización Pickle (Fickling)

Fickling descompila el archivo Pickle **sin ejecutarlo** y genera una representación Python equivalente. El scanner busca en esa representación palabras clave peligrosas como `exec`, `os.system`, `__reduce__`, etc.

Esta es la prueba más importante para archivos `.bin` y `.pkl`.

### 2. Análisis de operaciones inseguras (ModelScan)

ModelScan escanea los archivos de modelo buscando operadores Pickle inseguros (`GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ`) que permiten ejecutar código arbitrario. Soporta múltiples formatos: `.pkl`, `.bin`, `.h5`, `.safetensors`.

### 3. Hash SHA256

Calcula el hash SHA256 de cada archivo analizado. Este hash puede compararse contra el publicado oficialmente por el proveedor del modelo (HuggingFace) para verificar que el archivo no fue modificado.

```bash
# Verificar manualmente el hash de un archivo
sha256sum ./jinaai/jina-embeddings-v3/pytorch_model.bin

# Comparar con el hash oficial en HuggingFace:
# https://huggingface.co/jinaai/jina-embeddings-v3/blob/main/pytorch_model.bin
# → En la página verás el SHA256 oficial del archivo
```

---

## Interpretación de resultados

### 🟢 LIMPIO
No se detectaron patrones maliciosos. El modelo puede continuar el proceso de validación hacia producción.

### 🔴 PELIGROSO
Se detectaron una o más keywords peligrosas **no atribuibles a código legítimo de PyTorch**. El modelo **no debe desplegarse** hasta ser revisado manualmente por el equipo de seguridad.

Para cada keyword detectada, el reporte explica:
- Qué significa técnicamente
- En qué línea exacta del análisis aparece
- Qué riesgo concreto representa en un entorno bancario

### 🟡 INDETERMINADO
El scanner no pudo analizar el archivo (formato no reconocido, error de lectura, etc.). Requiere revisión manual.

---

## Reportes generados

El script genera automáticamente dos archivos con timestamp:

### `reporte_scan_YYYYMMDD_HHMMSS.txt`
Reporte legible en texto plano. Incluye toda la salida del scanner con el detalle de cada modelo. Útil para archivar y compartir con el equipo de seguridad.

### `reporte_scan_YYYYMMDD_HHMMSS.json`
Reporte estructurado en JSON. Útil para integrar con otras herramientas de seguridad, dashboards o pipelines CI/CD.

**Estructura del JSON:**
```json
{
  "fecha": "2026-03-31 21:18:58",
  "resumen": {
    "total": 4,
    "limpios": 4,
    "peligrosos": 0,
    "indeterminados": 0
  },
  "resultados": [
    {
      "archivo": "./jinaai/jina-embeddings-v3/pytorch_model.bin",
      "estado": "LIMPIO",
      "sha256": "a3f1b2c4d5e6...",
      "metodo": "fickling",
      "peligros": []
    }
  ]
}
```

---

## Directorios ignorados

El scanner omite automáticamente los siguientes directorios para evitar falsos positivos de librerías del sistema:

```
venv          .venv         env           .env
tmp_scan      .git          __pycache__
node_modules  .tox          dist          build
site-packages
```

---

## Falsos positivos — qué filtra

El scanner filtra automáticamente patrones que son código **legítimo de PyTorch** y que contienen keywords peligrosas pero no representan riesgo real:

| Patrón filtrado | Por qué es seguro |
|---|---|
| `_rebuild_tensor_v2` | Función estándar de PyTorch para reconstruir tensores |
| `_rebuild_parameter` | Función estándar de PyTorch para parámetros |
| `persistent_load` | Mecanismo interno de carga de PyTorch |
| `BFloat16Storage` | Tipo de almacenamiento de PyTorch |
| `FloatStorage` | Tipo de almacenamiento de PyTorch |
| `__setstate__` | Restauración de estado de módulos PyTorch |
| `OrderedDict` | Estructura de datos estándar Python |
| `_var*` | Variables internas generadas por Fickling |

---

## Limitaciones

| Limitación | Descripción |
|---|---|
| No verifica el hash contra HuggingFace | El hash SHA256 se calcula localmente. La comparación con el hash oficial debe hacerse manualmente en la página del modelo. |
| No analiza archivos de configuración | Los `config.json`, `tokenizer.json`, etc. no son escaneados (raramente contienen código malicioso, pero es posible). |
| No hace red teaming | No prueba el comportamiento del modelo en ejecución (prompt injection, jailbreak, etc.). Para eso se recomienda usar Garak o PyRIT por separado. |
| No detecta data poisoning | El envenenamiento de datos de entrenamiento no es detectable por análisis estático del archivo de pesos. |
| Timeout de 120–180 segundos | Modelos muy grandes pueden superar el timeout en sistemas lentos. |

---

## Recomendaciones para el banco

### Pipeline de validación completo sugerido

```
1. Firewall Sonatype IQ (Nexus)
   └─ Bloquea componentes en cuarentena antes de descargar

2. scan_models.py (este script)
   └─ Análisis estático del archivo de pesos
      ├─ Fickling  → detección de código malicioso en Pickle
      ├─ ModelScan → operaciones inseguras
      └─ SHA256    → trazabilidad del archivo

3. Verificación manual de hash
   └─ Comparar SHA256 generado vs publicado en HuggingFace

4. Red teaming (entorno aislado)
   └─ Garak o PyRIT para pruebas de comportamiento

5. Aprobación del equipo de seguridad
   └─ Sign-off antes del deploy a producción
```

### Preferir siempre `.safetensors`

Cuando existan versiones equivalentes de un modelo en formato `.safetensors`, preferirlas sobre `.bin`. El formato `.safetensors` fue diseñado específicamente para evitar la ejecución de código al cargar modelos y es el estándar recomendado por la comunidad de seguridad en IA.

### Nunca usar `torch.load()` sin `weights_only=True`

```python
# ❌ Peligroso — ejecuta código del archivo
modelo = torch.load("modelo.bin")

# ✅ Seguro — solo carga tensores
modelo = torch.load("modelo.bin", weights_only=True)
```

---

## Autores y contexto

Script desarrollado para el proceso de validación de seguridad de modelos IA en entorno bancario regulado. Complementa el firewall de Sonatype Nexus IQ con análisis estático a nivel de archivo de pesos.

**Herramientas de terceros utilizadas:**
- [Fickling](https://github.com/trailofbits/fickling) — Trail of Bits
- [ModelScan](https://github.com/protectai/modelscan) — Protect AI

**Referencias:**
- [OWASP Top 10 para LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [HuggingFace — Seguridad en Pickle](https://huggingface.co/docs/hub/security-pickle)
