"""Command-line entry point: health check, KEV ingestion, one-shot ask, interactive chat."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from viper import __version__
from viper.config import Settings, get_settings
from viper.llm import LLMError, OllamaClient
from viper.logging_setup import configure_logging
from viper.rag import Answer, IngestError, VectorStore, answer, ingest
from viper.rag.cisa_kev import fetch_kev, parse_kev
from viper.rag.embedding import PrefixEmbedder

log = logging.getLogger("viper.cli")


def _build(settings: Settings) -> tuple[OllamaClient, VectorStore]:
    llm = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    store = VectorStore(settings.qdrant_path, f"kb_{settings.kb_version}")
    return llm, store


def _print_answer(a: Answer) -> None:
    print(a.text)
    if a.sources:
        print("\nSources:")
        for i, h in enumerate(a.sources, 1):
            print(f"  [{i}] {h.document.title} - {h.document.url} (score {h.score:.2f})")
    if a.invalid_citations:
        print(f"\nWARNING: answer cites non-existent sources {a.invalid_citations}; do not trust it.")


def cmd_ingest_kev(settings: Settings, limit: int | None) -> int:
    llm, store = _build(settings)
    try:
        docs = parse_kev(fetch_kev())
        if limit:
            docs = docs[:limit]
        n = ingest(docs, PrefixEmbedder(llm, settings.embed_doc_prefix), store)
    except (IngestError, LLMError) as exc:
        print(f"Ingest failed: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"Ingested {n} CISA KEV records into {store.collection}.")
    return 0


def cmd_ask(settings: Settings, question: str | None) -> int:
    llm, store = _build(settings)
    qembed = PrefixEmbedder(llm, settings.embed_query_prefix)

    def ask(q: str) -> None:
        _print_answer(answer(q, qembed, store, llm, settings.retrieval_top_k, settings.min_score))

    try:
        if question:
            ask(question)
            return 0
        print("Viper chat (type 'exit' to quit). Answers cite sources; unsourced ones are marked.")
        while True:
            try:
                q = input("\nyou> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if q.lower() in {"exit", "quit"}:
                break
            if q:
                ask(q)
        return 0
    except LLMError as exc:
        print(f"Model error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()


def cmd_eval(settings: Settings, args: argparse.Namespace) -> int:
    from pathlib import Path

    from viper.eval import runner
    from viper.eval.build import build

    if args.eval_cmd == "build":
        store = VectorStore(settings.qdrant_path, f"kb_{settings.kb_version}")
        try:
            print(build(store))
        finally:
            store.close()
        return 0
    if args.eval_cmd == "compare":
        a, b = (json.loads(Path(f).read_text(encoding="utf-8")) for f in (args.a, args.b))
        for line in runner.compare(a, b):
            print(line)
        return 0
    only = set(args.only.split(",")) if args.only else None
    report = runner.run_eval(settings, args.tag, skip_llm=args.skip_llm, only=only)
    path = runner.save_report(report)
    print(json.dumps({"retrieval": report["retrieval"]["overall"],
                      "calibration": report["retrieval"]["calibration"],
                      "answers": report.get("answers", {}).get("summary")}, indent=1))
    print(f"Report saved: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="viper")
    parser.add_argument("--health", action="store_true", help="print redacted config and exit")
    sub = parser.add_subparsers(dest="command")
    p_ing = sub.add_parser("ingest-kev", help="download and index CISA KEV")
    p_ing.add_argument("--limit", type=int, default=None, help="index only the first N records")
    p_ask = sub.add_parser("chat", help="chat (or one-shot with a question)")
    p_ask.add_argument("question", nargs="?", default=None)
    p_eval = sub.add_parser("eval", help="evaluation framework")
    esub = p_eval.add_subparsers(dest="eval_cmd", required=True)
    esub.add_parser("build", help="regenerate frozen datasets from the indexed KEV snapshot")
    p_run = esub.add_parser("run", help="run evaluation and save a report")
    p_run.add_argument("--tag", required=True, help="name for this run, e.g. baseline-fsec-1.1")
    p_run.add_argument("--skip-llm", action="store_true", help="retrieval metrics only (fast)")
    p_run.add_argument("--only", default=None, help="comma list of case ids or categories")
    p_cmp = esub.add_parser("compare", help="compare two saved reports")
    p_cmp.add_argument("a")
    p_cmp.add_argument("b")
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level)

    if args.health:
        log.info("health check", extra={"version": __version__})
        print(json.dumps({"status": "OK", "version": __version__, "config": settings.redacted()}, indent=2))
        return 0
    if args.command == "ingest-kev":
        return cmd_ingest_kev(settings, args.limit)
    if args.command == "eval":
        return cmd_eval(settings, args)
    if args.command == "chat":
        return cmd_ask(settings, args.question)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
