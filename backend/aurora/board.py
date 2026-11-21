"""Tablero del estudiante: perfila SUS datos y sugiere cruces posibles, sin revelar respuestas.

Reglas para no regalar el resultado:
- columnas tipo «llave» (IPs, hosts, dominios, cuentas…): solo cuántos valores distintos hay, nunca los más frecuentes;
- no se muestran sumas ni totales de bytes;
- los cruces muestran cuántos valores comparten dos columnas, no cuáles.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

KEYLIKE = {"src_ip", "dst_ip", "ip", "ioc", "host", "usuario", "dominio", "sha256", "archivo", "c2_ip", "c2_dominio", "texto", "detalle", "id", "url"}
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _kind(vals: list) -> str:
    if not vals:
        return "text"
    if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "num"
    if all(isinstance(v, str) and _TS.match(v) for v in vals):
        return "time"
    return "text"


def _hist(vals: list[str], bins: int = 10) -> list[dict]:
    ts = []
    for v in vals:
        try:
            ts.append(datetime.fromisoformat(v.replace(" ", "T")[:19]))
        except ValueError:
            continue
    if len(ts) < 2:
        return []
    lo, hi = min(ts), max(ts)
    span = (hi - lo).total_seconds() or 1
    counts = [0] * bins
    for t in ts:
        counts[min(bins - 1, int((t - lo).total_seconds() / span * bins))] += 1
    step = span / bins
    return [{"label": (lo.fromtimestamp(lo.timestamp() + step * i)).strftime("%d %b %H:%M"), "n": c} for i, c in enumerate(counts)]


def profile(rows: list[dict]) -> dict:
    n = len(rows)
    cols = []
    for c in (rows[0].keys() if rows else []):
        vals = [r.get(c) for r in rows]
        nn = [v for v in vals if v not in (None, "")]
        kind = _kind(nn)
        distinct = len({str(v) for v in nn})
        info = {"name": c, "kind": kind, "nulls": n - len(nn), "distinct": distinct}
        if kind == "num" and nn:
            info.update(min=min(nn), max=max(nn), mean=round(sum(nn) / len(nn), 2))
        elif kind == "time":
            info["hist"] = _hist([str(v) for v in nn])
        elif kind == "text" and 1 < distinct <= 8 and c not in KEYLIKE:
            cnt: dict[str, int] = {}
            for v in nn:
                cnt[str(v)] = cnt.get(str(v), 0) + 1
            info["dist"] = sorted(({"value": k, "n": v} for k, v in cnt.items()), key=lambda x: -x["n"])
        cols.append(info)
    dup = n - len({json.dumps(r, sort_keys=True, default=str) for r in rows})
    return {"rows": n, "duplicates": dup, "columns": cols}


def relations(datasets: dict[str, list[dict]]) -> list[dict]:
    """Cruces posibles: pares de columnas de datasets distintos que comparten valores (solo el conteo)."""
    def keyvals(rows, c):
        return {str(r[c]).strip().lower() for r in rows if r.get(c) not in (None, "")}
    out = []
    names = list(datasets)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            ra, rb = datasets[a], datasets[b]
            if not ra or not rb:
                continue
            for ca in ra[0]:
                if ca not in KEYLIKE or ca in ("texto", "detalle", "id"):
                    continue
                va = keyvals(ra, ca)
                for cb in rb[0]:
                    if cb not in KEYLIKE or cb in ("texto", "detalle", "id"):
                        continue
                    common = va & keyvals(rb, cb)
                    if common:
                        out.append({"a": a, "col_a": ca, "b": b, "col_b": cb, "shared": len(common), "how": "valores iguales"})
    # texto libre: cuántos valores de otras columnas se mencionan dentro de los informes
    for name, rows in datasets.items():
        if not rows or "texto" not in rows[0]:
            continue
        blob = " ".join(str(r["texto"]).lower() for r in rows)
        for other, ro in datasets.items():
            if other == name or not ro:
                continue
            for c in ro[0]:
                if c in KEYLIKE and c not in ("texto", "detalle", "id"):
                    hit = {v for v in keyvals(ro, c) if len(v) > 5 and v in blob}
                    if hit:
                        out.append({"a": other, "col_a": c, "b": name, "col_b": "texto", "shared": len(hit), "how": "mencionados en los textos"})
    out.sort(key=lambda r: -r["shared"])
    return out[:14]
