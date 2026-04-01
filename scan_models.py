#!/usr/bin/env python3
"""
====================================================
  SCANNER AUTÓNOMO DE MODELOS IA
  Fickling + ModelScan + Hash SHA256
  Banco — v5.0

  USO:
    # Escanear una ruta específica
    python3 scan_models.py /ruta/al/modelo

    # Escanear múltiples rutas desde un archivo
    python3 scan_models.py -file modelos.txt

    # Escanear directorio actual
    python3 scan_models.py .

  FORMATO modelos.txt (una ruta por línea):
    ./jinaai/jina-embeddings-v3
    ./Helsinki-NLP/opus-mt-en-es
    /datos/modelos/llama3
====================================================
"""

import zipfile
import os
import sys
import glob
import subprocess
import shutil
import hashlib
import json
from datetime import datetime

# ─────────────────────────────────────────────
# EXTENSIONES A ESCANEAR
# ─────────────────────────────────────────────
EXTENSIONES_RIESGO  = [".bin", ".h5", ".pkl"]
EXTENSIONES_SEGURAS = [".safetensors"]
EXTENSIONES_TODAS   = EXTENSIONES_RIESGO + EXTENSIONES_SEGURAS

# ─────────────────────────────────────────────
# DIRECTORIOS A IGNORAR SIEMPRE
# ─────────────────────────────────────────────
DIRS_IGNORAR = [
    "venv", ".venv", "env", ".env",
    "tmp_scan", ".git", "__pycache__",
    "node_modules", ".tox", "dist", "build",
    "site-packages",
]

# ─────────────────────────────────────────────
# KEYWORDS PELIGROSAS
# ─────────────────────────────────────────────
PELIGROS_EXPLICADOS = {
    "__reduce__"   : "Ejecuta código arbitrario al deserializar el modelo",
    "exec"         : "Ejecuta código Python dinámico — vector de ejecución remota",
    "eval"         : "Evalúa y ejecuta strings como código Python",
    "os.system"    : "Ejecuta comandos del sistema operativo directamente",
    "subprocess"   : "Puede lanzar procesos del sistema operativo",
    "GLOBAL"       : "Importa módulos arbitrarios de Python durante la carga",
    "builtins.open": "Acceso arbitrario al sistema de archivos",
    "importlib"    : "Importación dinámica — puede cargar código externo",
    "pty"          : "Acceso a terminales — riesgo de shell inversa",
    "socket"       : "Conexiones de red — riesgo de exfiltración de datos",
    "shutil.rmtree": "Puede eliminar directorios del sistema de archivos",
    "newobj"       : "Opcode NEWOBJ: instancia clases arbitrarias",
}

RIESGO_BANCO = {
    "__reduce__"   : "RCE clásico via Pickle — puede comprometer el servidor completo.",
    "exec"         : "Ejecución directa de código — riesgo crítico en producción.",
    "eval"         : "Evaluación de código dinámico — puede ejecutar instrucciones inyectadas.",
    "os.system"    : "Ejecuta comandos del SO en el servidor bancario.",
    "subprocess"   : "Lanza procesos del sistema — riesgo de escalada de privilegios.",
    "GLOBAL"       : "Importa módulos no controlados — puede cargar librerías maliciosas.",
    "builtins.open": "Acceso libre al FS — puede leer/escribir datos sensibles.",
    "importlib"    : "Carga código externo dinámicamente — riesgo post-despliegue.",
    "pty"          : "Shell reversa hacia el atacante.",
    "socket"       : "Exfiltración de datos bancarios via red.",
    "shutil.rmtree": "Destrucción masiva de archivos en producción.",
    "newobj"       : "Instancia objetos arbitrarios en memoria.",
}

# ─────────────────────────────────────────────
# PATRONES LEGÍTIMOS DE PYTORCH (falsos positivos)
# ─────────────────────────────────────────────
FALSOS_POSITIVOS = [
    "_rebuild_tensor", "_rebuild_parameter",
    "persistent_load", "bfloat16storage",
    "floatstorage", "halfstorage", "bytestorage",
    "longstorage", "unsafeopsc", "__setstate__",
    "ordereddict", "_var",
]

LINEAS_BENIGNAS = [
    "no settings file", "using defaults", "no issues found",
    "total skipped", "run with --show-skipped",
    "scanning /", "--- summary ---", "--- skipped ---",
]

# ─────────────────────────────────────────────
# COLORES
# ─────────────────────────────────────────────
C = {
    "R" : "\033[91m",   # rojo
    "G" : "\033[92m",   # verde
    "Y" : "\033[93m",   # amarillo
    "B" : "\033[94m",   # azul
    "C" : "\033[96m",   # cyan
    "W" : "\033[97m",   # blanco
    "RST": "\033[0m",
    "BD" : "\033[1m",
    "DIM": "\033[2m",
}

def c(color, texto):
    return f"{C[color]}{texto}{C['RST']}"

LOG_LINES = []

def log(texto=""):
    limpio = texto
    for v in C.values():
        limpio = limpio.replace(v, "")
    LOG_LINES.append(limpio)
    print(texto)

def sep(char="─", n=64):
    log(c("DIM", char * n))

def titulo(texto, char="═"):
    log(c("BD", char * 64))
    log(c("BD", f"  {texto}"))
    log(c("BD", char * 64))

# ─────────────────────────────────────────────
# PARSEAR ARGUMENTOS
# ─────────────────────────────────────────────
def parsear_args():
    args = sys.argv[1:]

    if not args:
        print(f"""
{c('BD', 'USO:')}
  {c('G', 'python3 scan_models.py /ruta/modelo')}          ← escanea una ruta
  {c('G', 'python3 scan_models.py -file modelos.txt')}     ← escanea lista de rutas
  {c('G', 'python3 scan_models.py .')}                      ← escanea directorio actual

{c('BD', 'FORMATO modelos.txt')} (una ruta por línea, # para comentarios):
  ./jinaai/jina-embeddings-v3
  ./Helsinki-NLP/opus-mt-en-es
  # este es un comentario
  /datos/modelos/llama3
""")
        sys.exit(0)

    rutas = []

    if args[0] == "-file":
        if len(args) < 2:
            print(c("R", "❌ Falta el nombre del archivo después de -file"))
            sys.exit(1)
        archivo = args[1]
        if not os.path.exists(archivo):
            print(c("R", f"❌ Archivo no encontrado: {archivo}"))
            sys.exit(1)
        with open(archivo, "r") as f:
            for linea in f:
                linea = linea.strip()
                if linea and not linea.startswith("#"):
                    rutas.append(linea)
        if not rutas:
            print(c("Y", f"⚠️  El archivo '{archivo}' está vacío o solo tiene comentarios."))
            sys.exit(0)
    else:
        rutas = [args[0]]

    return rutas

# ─────────────────────────────────────────────
# DESCUBRIR ARCHIVOS DE MODELO EN UNA RUTA
# ─────────────────────────────────────────────
def descubrir_archivos(ruta):
    archivos = []

    if os.path.isfile(ruta):
        ext = os.path.splitext(ruta)[1].lower()
        if ext in EXTENSIONES_TODAS:
            archivos.append(ruta)
        return archivos

    if not os.path.isdir(ruta):
        log(c("Y", f"  ⚠️  Ruta no válida: {ruta}"))
        return archivos

    for ext in EXTENSIONES_TODAS:
        for f in glob.glob(os.path.join(ruta, "**", f"*{ext}"), recursive=True):
            # Ignorar directorios del sistema
            partes = f.replace("\\", "/").split("/")
            if any(d in partes for d in DIRS_IGNORAR):
                continue
            archivos.append(f)

    return sorted(set(archivos))

# ─────────────────────────────────────────────
# CALCULAR SHA256
# ─────────────────────────────────────────────
def sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"

# ─────────────────────────────────────────────
# FILTROS DE FALSOS POSITIVOS
# ─────────────────────────────────────────────
def es_falso_positivo(linea):
    ll = linea.lower()
    return any(p.lower() in ll for p in FALSOS_POSITIVOS)

def es_linea_benigna(linea):
    ll = linea.lower()
    return any(p.lower() in ll for p in LINEAS_BENIGNAS)

# ─────────────────────────────────────────────
# ANALIZAR CON FICKLING (ZIP PyTorch → .pkl)
# ─────────────────────────────────────────────
def analizar_fickling(filepath):
    tmp = "./tmp_scan_pkl"
    try:
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp, exist_ok=True)

        with zipfile.ZipFile(filepath, "r") as z:
            z.extractall(tmp)

        pkl_path = None
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith(".pkl"):
                    pkl_path = os.path.join(root, f)
                    break

        if not pkl_path:
            return None, "sin_pkl"

        r = subprocess.run(["fickling", pkl_path], capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr, "fickling"

    except zipfile.BadZipFile:
        r = subprocess.run(["modelscan", "-p", filepath], capture_output=True, text=True, timeout=180)
        return r.stdout + r.stderr, "modelscan_fallback"
    except Exception as e:
        return f"ERROR: {e}", "error"
    finally:
        if os.path.exists(tmp):
            shutil.rmtree(tmp)

# ─────────────────────────────────────────────
# ANALIZAR CON MODELSCAN
# ─────────────────────────────────────────────
def analizar_modelscan(filepath):
    try:
        r = subprocess.run(["modelscan", "-p", filepath], capture_output=True, text=True, timeout=180)
        return r.stdout + r.stderr, "modelscan"
    except Exception as e:
        return f"ERROR: {e}", "error"

# ─────────────────────────────────────────────
# EVALUAR RIESGO
# ─────────────────────────────────────────────
def evaluar(salida):
    if not salida:
        return "INDETERMINADO", {}

    salida_lower = salida.lower()
    lineas = salida.strip().split("\n")

    if "no issues found" in salida_lower:
        return "LIMPIO", {}

    peligros = {}
    for keyword, explicacion in PELIGROS_EXPLICADOS.items():
        sospechosas = []
        for linea in lineas:
            if not linea.strip():
                continue
            if es_falso_positivo(linea) or es_linea_benigna(linea):
                continue
            if keyword.lower() in linea.lower():
                sospechosas.append(linea.strip())
        if sospechosas:
            peligros[keyword] = {"explicacion": explicacion, "lineas": sospechosas}

    if peligros:
        return "PELIGROSO", peligros
    elif "error" in salida_lower and "no issues" not in salida_lower:
        return "ERROR", {}
    else:
        return "LIMPIO", {}

# ─────────────────────────────────────────────
# ESCANEAR UN ARCHIVO
# ─────────────────────────────────────────────
def escanear_archivo(filepath, idx, total):
    ext       = os.path.splitext(filepath)[1].lower()
    nombre    = filepath
    resultado = {
        "archivo"  : filepath,
        "extension": ext,
        "sha256"   : "",
        "estado"   : "INDETERMINADO",
        "metodo"   : "",
        "peligros" : {},
    }

    log()
    sep()
    log(c("BD", f"  [{idx}/{total}] {nombre}"))
    sep()
    log(c("DIM", f"  Extensión : {ext}"))

    # ── SHA256 ──
    log(c("DIM",  "  SHA256    : calculando..."), )
    hash_val = sha256(filepath)
    resultado["sha256"] = hash_val
    # Sobreescribir la línea con el hash real
    log(c("DIM", f"  SHA256    : {hash_val}"))

    # ── SAFETENSORS — solo modelscan ──
    if ext == ".safetensors":
        log(c("DIM",  "  Método    : MODELSCAN (formato seguro safetensors)"))
        salida, metodo = analizar_modelscan(filepath)
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    # ── BIN / PKL — fickling + fallback modelscan ──
    elif ext in [".bin", ".pkl"]:
        log(c("DIM",  "  Método    : FICKLING → MODELSCAN (fallback)"))
        salida, metodo = analizar_fickling(filepath)
        if metodo == "modelscan_fallback":
            log(c("Y", "  ℹ️  Fallback: no era ZIP PyTorch, se usó modelscan"))
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    # ── H5 — modelscan ──
    elif ext == ".h5":
        log(c("DIM",  "  Método    : MODELSCAN (formato HDF5/Keras)"))
        salida, metodo = analizar_modelscan(filepath)
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    else:
        log(c("Y", f"  ⚠️  Extensión no soportada: {ext}"))
        return resultado

    resultado["estado"]   = estado
    resultado["peligros"] = peligros

    # ── BANNER RESULTADO ──
    log()
    if estado == "PELIGROSO":
        log(c("R",  "  ╔═══════════════════════════════════════════╗"))
        log(c("R",  "  ║   🔴  RESULTADO: PELIGROSO                ║"))
        log(c("R",  "  ╚═══════════════════════════════════════════╝"))
    elif estado == "LIMPIO":
        log(c("G",  "  ╔═══════════════════════════════════════════╗"))
        log(c("G",  "  ║   🟢  RESULTADO: LIMPIO                   ║"))
        log(c("G",  "  ╚═══════════════════════════════════════════╝"))
    else:
        log(c("Y",  "  ╔═══════════════════════════════════════════╗"))
        log(c("Y",  f"  ║   🟡  RESULTADO: {estado:<26}║"))
        log(c("Y",  "  ╚═══════════════════════════════════════════╝"))

    # ── DETALLE DE PELIGROS ──
    if estado == "PELIGROSO" and peligros:
        log()
        log(c("R", "  " + "▓" * 52))
        log(c("R", c("BD", "  ⚠️  EXPLICACIÓN DE PELIGROS DETECTADOS")))
        log(c("R", "  " + "▓" * 52))

        for i, (kw, info) in enumerate(peligros.items(), 1):
            log()
            log(c("BD",  f"  [{i}] Keyword     : {c('R', kw)}"))
            log(c("Y",   f"      Significado : {info['explicacion']}"))
            log(c("Y",    "      Aparece en  :"))
            for linea in info["lineas"][:5]:
                log(c("C", f"        › {linea}"))
            riesgo = RIESGO_BANCO.get(kw, "Compromete el entorno de producción bancario.")
            log(c("Y",    "      Riesgo banco:"))
            log(c("R",   f"        ⚡ {riesgo}"))

        log()
        log(c("R", "  " + "▓" * 52))

    return resultado

# ─────────────────────────────────────────────
# VERIFICAR HERRAMIENTAS
# ─────────────────────────────────────────────
def verificar_herramientas():
    log(c("BD", "\n🔧 Verificando herramientas..."))
    ok = True
    for h in ["fickling", "modelscan"]:
        p = shutil.which(h)
        if p:
            log(c("G", f"   ✅ {h:<12} → {p}"))
        else:
            log(c("R", f"   ❌ {h:<12} → NO encontrado  (pip install {h})"))
            ok = False
    if not ok:
        log(c("R", "\n❌ Instala las herramientas faltantes antes de continuar."))
        sys.exit(1)

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    fecha          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts             = datetime.now().strftime("%Y%m%d_%H%M%S")
    reporte_txt    = f"reporte_scan_{ts}.txt"
    reporte_json   = f"reporte_scan_{ts}.json"

    rutas_input = parsear_args()

    titulo("🔐 SCANNER AUTÓNOMO DE MODELOS IA — v5.0")
    log(c("DIM", f"  Fecha        : {fecha}"))
    log(c("DIM", f"  Rutas input  : {len(rutas_input)}"))
    for r in rutas_input:
        log(c("DIM", f"    • {r}"))

    verificar_herramientas()

    # ── Descubrir todos los archivos ──
    log(c("BD", "\n🔍 Descubriendo archivos de modelo..."))
    todos_archivos = []
    for ruta in rutas_input:
        encontrados = descubrir_archivos(ruta)
        log(c("DIM", f"  {ruta} → {len(encontrados)} archivo(s)"))
        todos_archivos.extend(encontrados)

    todos_archivos = sorted(set(todos_archivos))

    if not todos_archivos:
        log(c("Y", "\n⚠️  No se encontraron archivos de modelo para escanear."))
        log(c("Y",  "   Extensiones buscadas: .bin .h5 .pkl .safetensors"))
        sys.exit(0)

    log(c("BD", f"\n  Total archivos a escanear: {c('W', str(len(todos_archivos)))}"))

    # ── Escanear cada archivo ──
    resultados = []
    for idx, filepath in enumerate(todos_archivos, 1):
        r = escanear_archivo(filepath, idx, len(todos_archivos))
        resultados.append(r)

    # ── RESUMEN FINAL ──
    log()
    titulo("📋 RESUMEN EJECUTIVO DE SEGURIDAD")
    log()

    peligrosos    = [r for r in resultados if r["estado"] == "PELIGROSO"]
    limpios       = [r for r in resultados if r["estado"] == "LIMPIO"]
    indeterminados = [r for r in resultados if r["estado"] not in ("PELIGROSO", "LIMPIO")]

    log(c("BD",  f"  Total escaneados  : {len(resultados)}"))
    log(c("G",   f"  🟢 Limpios         : {len(limpios)}"))
    log(c("R",   f"  🔴 Peligrosos      : {len(peligrosos)}"))
    log(c("Y",   f"  🟡 Indeterminados  : {len(indeterminados)}"))
    log()
    sep()

    for r in resultados:
        nombre_corto = r["archivo"]
        hash_corto   = r["sha256"][:16] + "..." if len(r["sha256"]) > 16 else r["sha256"]

        if r["estado"] == "PELIGROSO":
            log(c("R",  f"  🔴 PELIGROSO  │ {nombre_corto}"))
            log(c("DIM",f"               │ SHA256: {hash_corto}"))
            for kw in r["peligros"]:
                log(c("Y", f"               │  ↳ [{kw}] {PELIGROS_EXPLICADOS[kw][:48]}..."))
        elif r["estado"] == "LIMPIO":
            log(c("G",  f"  🟢 LIMPIO     │ {nombre_corto}"))
            log(c("DIM",f"               │ SHA256: {hash_corto}"))
        else:
            log(c("Y",  f"  🟡 {r['estado']:<10}│ {nombre_corto}"))
            log(c("DIM",f"               │ SHA256: {hash_corto}"))

    sep()
    log()

    if peligrosos:
        log(c("R", c("BD", "  🚨 ACCIÓN RECOMENDADA:")))
        log(c("Y",  "  Los modelos PELIGROSOS NO deben desplegarse en producción."))
        log(c("Y",  "  Notificar al equipo de seguridad y reemplazar por"))
        log(c("Y",  "  versiones .safetensors si están disponibles en HuggingFace."))
    else:
        log(c("G", c("BD", "  ✅ Ningún modelo presenta peligros reales.")))
        log(c("DIM", "  Nota: los modelos .bin/pkl son formato Pickle (menos seguro que"))
        log(c("DIM", "  .safetensors). Migrar si existen equivalentes disponibles."))

    log()
    sep()

    # ── Guardar reportes ──
    with open(reporte_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(LOG_LINES))

    reporte_data = {
        "fecha"    : fecha,
        "resumen"  : {
            "total"        : len(resultados),
            "limpios"      : len(limpios),
            "peligrosos"   : len(peligrosos),
            "indeterminados": len(indeterminados),
        },
        "resultados": [
            {
                "archivo" : r["archivo"],
                "estado"  : r["estado"],
                "sha256"  : r["sha256"],
                "metodo"  : r["metodo"],
                "peligros": list(r["peligros"].keys()),
            }
            for r in resultados
        ],
    }
    with open(reporte_json, "w", encoding="utf-8") as f:
        json.dump(reporte_data, f, indent=2, ensure_ascii=False)

    log(c("G",  f"\n  ✅ Reporte TXT  : {reporte_txt}"))
    log(c("G",  f"  ✅ Reporte JSON : {reporte_json}"))
    log(c("BD", "═" * 64 + "\n"))

if __name__ == "__main__":
    main()
