import re, zlib, base64

def _decode_pdf_str(b):
    out = bytearray()
    i = 0
    while i < len(b):
        c = b[i]
        if c == 0x5c:
            if i+1 < len(b):
                n = b[i+1]
                if n == ord('n'): out.append(10); i += 2; continue
                if n == ord('r'): out.append(13); i += 2; continue
                if n == ord('t'): out.append(9); i += 2; continue
                if n in (ord('('), ord(')'), ord('\\')): out.append(n); i += 2; continue
                if 48 <= n <= 55:
                    octs = b[i+1:i+4]
                    val = 0; consumed = 0
                    for ch in octs:
                        if 48 <= ch <= 55:
                            val = val*8 + (ch-48); consumed += 1
                        else: break
                    out.append(val & 0xff); i += 1 + consumed; continue
                out.append(n); i += 2; continue
        out.append(c); i += 1
    try: return out.decode("latin-1")
    except Exception: return out.decode("utf-8", errors="replace")

def _decompress_stream(raw):
    raw = raw.strip()
    if raw.endswith(b"~>"):
        raw = raw[:-2].strip()
    # try direct flate
    try:
        return zlib.decompress(raw)
    except Exception:
        pass
    # try ascii85 then flate
    try:
        dec85 = base64.a85decode(raw, adobe=False)
        try:
            return zlib.decompress(dec85)
        except Exception:
            return dec85
    except Exception:
        pass
    return raw

def extract_pdf_text(path):
    with open(path, "rb") as f:
        data = f.read()
    texts = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        dec = _decompress_stream(m.group(1))
        if not (re.search(rb"\)\s*Tj", dec) or re.search(rb"\]\s*TJ", dec)):
            continue
        for tm in re.finditer(rb"\((?:\\.|[^()])*\)\s*Tj", dec):
            inner = re.search(rb"\((.*)\)\s*Tj", tm.group(0), re.S)
            if inner:
                texts.append(_decode_pdf_str(inner.group(1)))
        for tm in re.finditer(rb"\[(.*?)\]\s*TJ", dec, re.S):
            arr = tm.group(1)
            for sm in re.finditer(rb"\((?:\\.|[^()])*\)", arr):
                texts.append(_decode_pdf_str(sm.group(0)[1:-1]))
    return " ".join(texts)