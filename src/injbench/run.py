"""Run the payload x defence x model matrix and write raw results plus a summary."""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .judge import judge
from .payloads import BY_ID, PAYLOADS
from .pipeline import PROMPTS, build_report
from .providers import MODELS, RateLimited, available, chat, load_env

RAW_DIR = Path("results/raw")


def run(models, defences, repeats: int, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():  # resume after a rate-limit stop
        for line in out.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done.add((r["model"], r["defence"], r["payload"], r["rep"]))
    with out.open("a", encoding="utf-8") as fh:
        for m in models:
            _run_model(m, defences, repeats, done, fh)


def _run_model(m, defences, repeats, done, fh) -> None:
    jobs = [(d, p, rep) for d in defences for p in PAYLOADS for rep in range(repeats)
            if (m.key, d, p.id, rep) not in done]
    for d, p, rep in jobs:
        report = build_report(p.agent_name)
        t0 = time.monotonic()
        try:
            raw, err = chat(m, PROMPTS[d](report)), None
        except RateLimited as e:
            print(f"stopping {m.key}: {e}")
            return
        except RuntimeError as e:
            # a 4xx means a bad model id or key; repeating it only burns quota
            print(f"stopping {m.key}: {str(e)[:200]}")
            return
        v = judge(raw, p, report)
        fh.write(json.dumps({
            "model": m.key, "defence": d, "payload": p.id, "rep": rep,
            "parsed": v.parsed, "echoed": v.echoed, "obeyed": v.obeyed,
            "flagged": v.flagged, "error": err, "raw": raw,
            "secs": round(time.monotonic() - t0, 2),
        }, ensure_ascii=False) + "\n")
        fh.flush()
        print(f"{m.key:18} {d} {p.id:22} rep{rep} obeyed={v.obeyed} echoed={v.echoed} flagged={v.flagged}")


def rescore(paths: list[Path]) -> int:
    """Re-judge stored replies after a scoring change, without new API calls."""
    changed = 0
    for path in paths:
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        for r in rows:
            if r["error"] is not None:
                continue
            p = BY_ID[r["payload"]]
            v = judge(r["raw"], p, build_report(p.agent_name))
            new = {"parsed": v.parsed, "echoed": v.echoed, "obeyed": v.obeyed, "flagged": v.flagged}
            if any(r[k] != new[k] for k in new):
                changed += 1
            r.update(new)
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return changed


def summarise(paths: list[Path], out_md: Path) -> str:
    rows = [json.loads(l) for p in paths for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if r["error"] is None]
    attack = [r for r in rows if r["payload"] != "control"]

    def rate(rs, key):
        return f"{100 * sum(r[key] for r in rs) / len(rs):.0f}%" if rs else "-"

    by = defaultdict(list)
    for r in attack:
        by[(r["model"], r["defence"])].append(r)
    models = sorted({r["model"] for r in rows})
    lines = ["## Attack success by model and defence", "",
             "Obeyed = the model acted on the injected instruction. Undetected = obeyed and the D2 post-check did not flag it.", "",
             "| Model | D0 obeyed | D0 + post-check undetected | D1 obeyed | D1 + post-check (D2) undetected | D0 echoed | D1 echoed |",
             "|---|---|---|---|---|---|---|"]
    for m in models:
        d0, d1 = by[(m, "D0")], by[(m, "D1")]
        und0 = f"{100 * sum(r['obeyed'] and not r['flagged'] for r in d0) / len(d0):.0f}%" if d0 else "-"
        und1 = f"{100 * sum(r['obeyed'] and not r['flagged'] for r in d1) / len(d1):.0f}%" if d1 else "-"
        lines.append(f"| {m} | {rate(d0, 'obeyed')} | {und0} | {rate(d1, 'obeyed')} | {und1} | "
                     f"{rate(d0, 'echoed')} | {rate(d1, 'echoed')} |")

    lines += ["", "## Attack success by payload (all models)", "", "| Payload | D0 obeyed | D1 obeyed | D2 undetected |", "|---|---|---|---|"]
    byp = defaultdict(list)
    for r in attack:
        byp[(r["payload"], r["defence"])].append(r)
    for p in [p.id for p in PAYLOADS if p.id != "control"]:
        d0, d1 = byp[(p, "D0")], byp[(p, "D1")]
        und = f"{100 * sum(r['obeyed'] and not r['flagged'] for r in d1) / len(d1):.0f}%" if d1 else "-"
        lines.append(f"| {p} | {rate(d0, 'obeyed')} | {rate(d1, 'obeyed')} | {und} |")

    control = [r for r in rows if r["payload"] == "control"]
    lines += ["", f"Control runs (no attack): {len(control)}; post-check false-alarm rate {rate(control, 'flagged')}; "
              f"JSON parse rate over all runs {rate(rows, 'parsed')}.", "",
              f"Runs: {len(rows)} successful calls; generated {datetime.now(timezone.utc):%Y-%m-%d}."]
    md = "\n".join(lines) + "\n"
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(md, encoding="utf-8")
    return md


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--models", nargs="*", help="model keys; default: every model with an API key")
    r.add_argument("--defences", nargs="*", default=["D0", "D1"])
    r.add_argument("--repeats", type=int, default=3)
    r.add_argument("--out", type=Path, default=RAW_DIR / "results.jsonl")
    rs = sub.add_parser("rescore")
    rs.add_argument("--raw", type=Path, nargs="*", default=sorted(RAW_DIR.glob("*.jsonl")))
    s = sub.add_parser("summary")
    s.add_argument("--raw", type=Path, nargs="*", default=sorted(RAW_DIR.glob("*.jsonl")))
    s.add_argument("--out", type=Path, default=Path("results/summary.md"))
    a = ap.parse_args()
    load_env()
    if a.cmd == "run":
        models = available()
        if a.models:
            models = [m for m in MODELS if m.key in a.models and m in models]
        if not models:
            raise SystemExit("no models with an API key; fill in .env (see .env.example)")
        run(models, a.defences, a.repeats, a.out)
    elif a.cmd == "rescore":
        print(f"{rescore(a.raw)} verdicts changed")
    else:
        print(summarise(a.raw, a.out))


if __name__ == "__main__":
    main()
