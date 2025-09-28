#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deserialization — mapeo rápido de (de)serialización insegura
- Fingerprinting de blobs y respuestas (PHP/Python/JSON/XML/Java/.NET/Ruby)
- Sondeo HTTP con cargas "canario" 
- Caja blanca: grep de repos PHP y Python (sinks, gadgets, PHAR, Pickle, YAML, JSON, XML)
- Sugerencias de gadget hunting (quebuscar en libs/confs)
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns

console = Console()

HEX = lambda b: binascii.hexlify(b).lower()


# FINGERPRINT 
# =========================
def guess_format(blob: bytes):
    hits = []
    h = HEX(blob)
    try:
        text = blob.decode("utf-8", errors="ignore")
    except Exception:
        text = None

    # --- PHP serialize
    if text and re.search(r'^(?:O:\d+:"|a:\d+:{|s:\d+:"|i:\d+;|b:[01];|d:\d+(?:\.\d+)?;)', text):
        hits.append(("php_serialize", 'Tokens s:/i:/a:/O: visibles (PHP)'))

    # --- Python Pickle 
    if len(blob) > 2 and blob[0] == 0x80 and blob[1] in (1,2,3,4,5) and blob.endswith(b'.'):
        hits.append((f'pickle_v{blob[1]}', '0x80 0x0X... y STOP "." (Python pickle)'))

    # --- Python Pickle v0 textual 
    if text and re.search(r"^\(lp\d+\nS'.*?'\np\d+\na", text):
        hits.append(("pickle_v0_text", "Protocolo 0 (texto)"))

    # --- JSON y variantes
    if text and text.strip().startswith(('{','[')):
        if re.search(r'"\$type"\s*:\s*"', text) or re.search(r'"@class"\s*:\s*"', text) or re.search(r'"@type"\s*:\s*"', text):
            hits.append(("json_typed", 'JSON con discriminadores ($type/@class/@type)'))
        else:
            hits.append(("json", 'JSON plano'))
    # JSONPickle (lista de strings/objetos con "py/object")
    if text and re.search(r'"py/object"\s*:\s*"', text):
        hits.append(("jsonpickle", 'JSONPickle (py/object)'))

    # --- YAML
    if text and re.search(r'(?m)^\s*-\s+.+', text) and ('{' not in text or '}' not in text):
        hits.append(("yaml", 'Secuencias YAML (posible PyYAML/ruamel)'))
    if text and re.search(r'(?m)^\s*!\w', text):
        hits.append(("yaml_tagged", 'YAML con etiquetas personalizadas (!Tag)'))

    # --- XML
    if text and text.strip().startswith('<'):
        if re.search(r'<!DOCTYPE\s', text, re.I) or re.search(r'<!ENTITY\s', text, re.I):
            hits.append(("xml_xxe_risk", 'XML con DOCTYPE/ENTITY (XXE/SSRF)'))
        # .NET NetDataContract / DataContract
        if 'http://schemas.microsoft.com/2003/10/Serialization/' in text or 'z:Type=' in text:
            hits.append((".net_netdatacontract", "NetDataContract-like (z:Type, z:Assembly)"))
        # XMLSerializer típico
        if re.search(r'xmlns(:\w+)?="http://www\.w3\.org/2001/XMLSchema(-instance)?"', text):
            hits.append((".net_xmlserializer_style", "XMLSerializer/DataContractSerializer-style"))

    # --- Java serialized
    if h.startswith(b'aced0005'):
        hits.append(("java_serial", 'Magic AC ED 00 05 (Java)'))
    # --- .NET BinaryFormatter
    if h.startswith(b'0001000000ffffffff'):
        hits.append((".net_binfmt", 'Magic 00 01 00 00 00 ff ff ff ff (.NET BinaryFormatter)'))
    # --- Ruby Marshal
    if h.startswith(b'0408'):
        hits.append(("ruby_marshal", 'Magic 0x04 0x08 (Ruby Marshal)'))

    # --- Base64 envoltorio
    if text and re.fullmatch(r'[A-Za-z0-9+/=\s]+', text.strip()) and len(text.strip()) % 4 == 0:
        try:
            dec = base64.b64decode(text.strip(), validate=True)
            inner = guess_format(dec)
            if inner and inner[0][0] != 'unknown':
                hits.append(("base64_wrapped", f'Parece Base64 de {", ".join(t for t,_ in inner)}'))
        except Exception:
            pass

    return hits or [("unknown", "Sin match claro")]


#  HTTP (CANARIOS)
# =========================
def http_probe(url, param, method='POST', extra_params=None):
    session = requests.Session()
    canaries = []

    # PHP serialize inocuo
    php_ser = 'a:1:{s:4:"HTB";s:5:"test1";}'
    canaries.append(('php_serialize_b64', base64.b64encode(php_ser.encode()).decode()))

    # Pickle inocuo 
    canaries.append(('pickle_p4_b64', base64.b64encode(b'\x80\x04]\x94(K\x01K\x02e.').decode()))

    # JSON con discriminadores 
    canaries.append(('json_typed_dotnet', json.dumps({"$type":"System.Object"})))
    canaries.append(('json_typed_jackson', json.dumps({"@class":"java.lang.Object"})))

    # YAML sequence
    canaries.append(('yaml_seq', "- 1\n- 2\n- 3\n"))

    # XML “segura” + XXE canario (entidad inerte)
    canaries.append(('xml_basic', "<root><ping>HTB</ping></root>"))
    canaries.append(('xml_xxe_canary', """<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY htb "HTB"> ]>
<root>&htb;</root>"""))

    results = []
    for name, val in canaries:
        data = {param: val}
        if extra_params:
            data.update(extra_params)
        try:
            if method.upper() == 'GET':
                r = session.get(url, params=data, timeout=10, allow_redirects=True)
            else:
                r = session.post(url, data=data, timeout=10, allow_redirects=True)
            reflects = (isinstance(val, str) and val[:80] in r.text) if hasattr(r, "text") else False
            import_msg = any(s in (r.text or "") for s in [
                "Imported", "unserialize", "TypeNameHandling", "error", "exception"
            ])
            results.append({
                'payload': name,
                'status': r.status_code,
                'length': len(r.content or b''),
                'reflects': reflects,
                'hint': 'msgs' if import_msg else ''
            })
        except Exception as e:
            results.append({'payload': name, 'error': str(e)})
    return results


# CAJA BLANCA
# =========================

# --- PHP focus (PHAR sinks, magic methods + sinks)
PHAR_HINTS = [
    r'file_exists\s*\(',
    r'file_get_contents\s*\(',
    r'is_file\s*\(',
    r'fopen\s*\(',
    r'\bscandir\s*\(',
    r'\bsplfileinfo\b',
]
DANG_FUNCS = [
    r'\bexec\s*\(',
    r'\bsystem\s*\(',
    r'\bpopen\s*\(',
    r'\bshell_exec\s*\(',
    r'\bpassthru\s*\(',
    r'\bproc_open\s*\(',
    r'\binclude\s*\(',
    r'\brequire\s*\(',
    r'\beval\s*\(',
]
MAGIC_METHODS = [r'function\s+__wakeup\s*\(', r'function\s+__destruct\s*\(']

def scan_php_repo(root: Path):
    findings = {'phar_sinks': [], 'magic_gadgets': [], 'serialize_calls': [], 'unserialize_calls': []}
    for p in root.rglob('*.php'):
        try:
            s = p.read_text('utf-8', errors='ignore')
        except Exception:
            continue
        if 'serialize(' in s:
            findings['serialize_calls'].append(str(p))
        if 'unserialize(' in s:
            findings['unserialize_calls'].append(str(p))
        if any(re.search(pat, s) for pat in PHAR_HINTS):
            findings['phar_sinks'].append(str(p))
        if any(re.search(mm, s) for mm in MAGIC_METHODS) and any(re.search(fn, s) for fn in DANG_FUNCS):
            findings['magic_gadgets'].append(str(p))
    return findings

# --- Python focus (pickle/yaml/jsonpickle/xml)
PY_RISK_CALLS = [
    r'\bpickle\.loads?\s*\(',
    r'\bpickle\.Unpickler\(',
    r'\bmarshal\.loads?\s*\(',
    r'\bjsonpickle\.decode\s*\(',
    r'\byaml\.load\s*\(',                 # inseguro
    r'\bruamel\.yaml\.YAML\(\)',
    r'\bxml\.etree\.ElementTree\.fromstring\s*\(',
    r'\bxml\.dom\.minidom\.parseString\s*\(',
]
PY_SAFE_YAML = [r'\byaml\.safe_load\s*\(']
PY_NET_BRIDGES = [
    r'BinaryFormatter', r'NetDataContractSerializer', r'LosFormatter', r'DataContractSerializer',
]

def scan_py_repo(root: Path):
    f = {'pickle':[], 'yaml_insecure':[], 'jsonpickle':[], 'xml_parsers':[], 'bridges_dotnet':[]}
    for p in root.rglob('*.py'):
        try:
            s = p.read_text('utf-8', errors='ignore')
        except Exception:
            continue
        if re.search(r'\bpickle\.', s):
            if re.search(r'\bpickle\.loads?\s*\(', s) or re.search(r'\bUnpickler\(', s):
                f['pickle'].append(str(p))
        if re.search(r'jsonpickle\.decode', s):
            f['jsonpickle'].append(str(p))
        if re.search(r'yaml\.load\s*\(', s):
            if not re.search(r'yaml\.safe_load\s*\(', s):
                f['yaml_insecure'].append(str(p))
        if re.search(r'xml\.(etree|dom)\.', s):
            if re.search(r'fromstring\s*\(|parseString\s*\(', s):
                f['xml_parsers'].append(str(p))
        if any(x in s for x in PY_NET_BRIDGES):
            f['bridges_dotnet'].append(str(p))
    return f

# --- (jackson/newton)
GEN_JSON_XML = {
    'jackson_enableDefaultTyping': re.compile(r'enableDefaultTyping|@JsonTypeInfo', re.I),
    'newtonsoft_typename': re.compile(r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Objects|Auto|Arrays)', re.I),
    'xmlresolver_enable': re.compile(r'XmlResolver\s*=', re.I),
}
def scan_generic_repo(root: Path):
    matches = {k:[] for k in GEN_JSON_XML}
    for p in root.rglob('*.*'):
        if p.suffix.lower() not in ('.java','.cs','.config','.xml','.json','.js','.ts','.php','.py'):
            continue
        try:
            s = p.read_text('utf-8', errors='ignore')
        except Exception:
            continue
        for key, rx in GEN_JSON_XML.items():
            if rx.search(s):
                matches[key].append(str(p))
    return matches

# GADGET HINTS / CHEATSHEET
# (para guiarpruebas)
# =========================

GADGET_HINTS = [
    # PHP
    ("php_serialize", [
        "Busca __wakeup/__destruct con include/require/exec/system",
        "PHAR vía wrappers phar:// + file_exists/fopen (metadatos serializados en PHP<=7.x)",
        "Laravel Blade: variables sin escape {!! ... !!} → XSS tras inyección de objeto",
    ]),
    # Pickle
    ("pickle", [
        "Cualquier clase Python con __reduce__/__reduce_ex__ maliciosa ejecuta RCE al loads()",
        "Busca usos de pickle.loads(data) con datos controlados por usuario",
    ]),
    # JSON typed (.NET / Java)
    ("json_typed", [
        "Newtonsoft.Json: TypeNameHandling != None → setters/constructores/TypeConverters (RCE)",
        "Jackson @class/@type enableDefaultTyping → setters no-estrictos (JdbcRowSetImpl, JNDI)",
        "Entrada tipo objeto System.Object / java.lang.Object en el grafo → punto de inyección",
    ]),
    # XML
    ("xml_xxe_risk", [
        "XXE/SSRF si DOCTYPE/ENTITY habilitados (deshabilitar DTD/External Entities)",
        "En .NET antiguos: XmlTextReader sin endurecer cargaba entidades externas",
    ]),
    # .NET BinaryFormatter
    (".net_binfmt", [
        "BinaryFormatter/NetDataContract/LosFormatter → callbacks & setters → RCE gadgets",
        "PSObject (PowerShell) constructor de serialización → CLI XML → conversores/Parse/XAML",
    ]),
    # Java serialization
    ("java_serial", [
        "Clásicos ysoserial; pero con JSON (Jackson/Genson) el vector pasa por setters + @class",
    ]),
]

# RENDER 

def render_hits_table(title, hits):
    t = Table(title=title, box=box.SIMPLE_HEAVY, show_lines=False)
    t.add_column("Formato / Señal", style="bold")
    t.add_column("Por qué")
    for tname, why in hits:
        t.add_row(tname, why)
    console.print(t)

def render_http_results(results):
    t = Table(title=" HTTP (canarios)", box=box.SIMPLE_HEAVY)
    t.add_column("Payload")
    t.add_column("Status", justify="right")
    t.add_column("Len", justify="right")
    t.add_column("Refleja", justify="center")
    t.add_column("Hint", justify="left")
    for r in results:
        if 'error' in r:
            t.add_row(r['payload'], Text("ERR", style="red"), "-", "-", r['error'])
        else:
            t.add_row(r['payload'], str(r['status']), str(r['length']),
                      "✔" if r['reflects'] else "–", r['hint'])
    console.print(t)

def render_php_findings(f):
    cols = []
    for title, key, color in [
        ("PHAR sinks sospechosos", 'phar_sinks', 'yellow'),
        ("Clases con __wakeup/__destruct + sinks peligrosos", 'magic_gadgets', 'red'),
        ("serialize() vistos", 'serialize_calls', 'cyan'),
        ("unserialize() vistos", 'unserialize_calls', 'magenta'),
    ]:
        listing = "\n".join(f[key]) if f[key] else "–"
        cols.append(Panel(listing, title=title, border_style=color))
    console.print(Columns(cols))

def render_py_findings(f):
    cols = []
    mapping = [
        ("pickle (loads/Unpickler)", 'pickle', 'red'),
        ("YAML inseguro (yaml.load)", 'yaml_insecure', 'yellow'),
        ("jsonpickle.decode", 'jsonpickle', 'magenta'),
        ("XML parsers (fromstring/parseString)", 'xml_parsers', 'cyan'),
        (".NET bridges referenciados", 'bridges_dotnet', 'green'),
    ]
    for title, key, color in mapping:
        listing = "\n".join(f[key]) if f[key] else "–"
        cols.append(Panel(listing, title=title, border_style=color))
    console.print(Columns(cols))

def render_generic_findings(f):
    cols = []
    labels = {
        'jackson_enableDefaultTyping': 'Jackson enableDefaultTyping/@JsonTypeInfo',
        'newtonsoft_typename': 'Json.NET TypeNameHandling != None',
        'xmlresolver_enable': 'XmlResolver asignado (posible XXE)',
    }
    for key, title in labels.items():
        listing = "\n".join(f[key]) if f[key] else "–"
        cols.append(Panel(listing, title=title, border_style='white'))
    console.print(Columns(cols))

def render_gadget_hints(formats_found):
    items = []
    for fmt, tips in GADGET_HINTS:
        if any(fmt in f for f,_ in formats_found) or fmt in ("json_typed",".net_binfmt","java_serial","pickle","php_serialize","xml_xxe_risk"):
            items.append(Panel("\n".join(f"- {t}" for t in tips), title=f"Sugerencias gadgets: {fmt}", border_style="bright_blue"))
    if items:
        console.print(Columns(items))

def suggested_queries(formats_found):
    q = []
    for f,_ in formats_found:
        if f == "php_serialize":
            q += [
                'site:github.com PHP __wakeup __destruct unserialize',
                'phar deserialization file_exists wrapper phar:// exploit',
            ]
        if f.startswith("pickle"):
            q += [
                'python pickle __reduce__ gadget rce',
                'unsafe pickle.loads user input audit'
            ]
        if f == "json_typed":
            q += [
                'Json.NET TypeNameHandling RCE gadget ObjectDataProvider',
                'Jackson enableDefaultTyping JdbcRowSetImpl @class gadget',
            ]
        if f == "xml_xxe_risk":
            q += ['XXE payload cheat sheet', '.NET XmlResolver disable DTD entity']
        if f == ".net_binfmt":
            q += [
                'BinaryFormatter PSObject gadget XamlReader Parse RCE',
                'LosFormatter DataContractSerializer gadget TypeConverter'
            ]
        if f == "java_serial":
            q += ['ysoserial gadget list', 'Jackson @class JdbcRowSetImpl setAutoCommit']
    # dedup
    seen = set()
    deduped = []
    for s in q:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped

def main():
    ap = argparse.ArgumentParser(description="Desearch — mapeo rápido")
    ap.add_argument('input', nargs='?', help='Archivo a fingerprint (raw o base64)')
    ap.add_argument('--as-base64', action='store_true', help='Forzar decodificar base64 antes de fingerprint')
    ap.add_argument('--url', help='Endpoint a sondear (GET/POST)')
    ap.add_argument('--param', help='Nombre de parámetro de datos a probar (p.ej. settings, data, payload)')
    ap.add_argument('--method', default='POST', help='GET/POST (default POST)')
    ap.add_argument('--extra', help='Parámetros extra URL-encoded, ej: "import=1&action=import"')
    ap.add_argument('--scan-php', help='Ruta a repo PHP (caja blanca)')
    ap.add_argument('--scan-py', help='Ruta a repo Python (caja blanca)')
    ap.add_argument('--scan-generic', help='Ruta a repo genérico (busca Jackson/Json.NET/XmlResolver)')
    args = ap.parse_args()

    console.print(Panel(Text("Desearch", style="bold"), border_style="green"))

    if args.input:
        b = Path(args.input).read_bytes()
        if args.as_base64:
            try:
                b = base64.b64decode(b, validate=False)
            except Exception:
                pass
        hits = guess_format(b)
        render_hits_table("Fingerprint del archivo", hits)
        render_gadget_hints(hits)
        qs = suggested_queries(hits)
        if qs:
            console.print(Panel("\n".join(f"• {s}" for s in qs), title="Búsquedas sugeridas", border_style="purple"))

    if args.url and args.param:
        extra = dict(urllib.parse.parse_qsl(args.extra)) if args.extra else None
        console.print(Panel(f"[bold]Sondeo HTTP[/bold]: {args.method.upper()} {args.url}  param={args.param}", border_style="cyan"))
        res = http_probe(args.url, args.param, args.method, extra_params=extra)
        render_http_results(res)

    if args.scan_php:
        console.print(Panel(f"Escaneo PHP: {args.scan_php}", border_style="yellow"))
        f = scan_php_repo(Path(args.scan_php))
        render_php_findings(f)

    if args.scan_py:
        console.print(Panel(f"Escaneo Python: {args.scan_py}", border_style="yellow"))
        f = scan_py_repo(Path(args.scan_py))
        render_py_findings(f)

    if args.scan_generic:
        console.print(Panel(f"Escaneo genérico (JSON/XML conf): {args.scan_generic}", border_style="yellow"))
        f = scan_generic_repo(Path(args.scan_generic))
        render_generic_findings(f)

    console.print(Panel("Hecho. Recuerda validar hallazgos con pruebas manuales controladas.", border_style="green"))

if __name__ == '__main__':
    main()
