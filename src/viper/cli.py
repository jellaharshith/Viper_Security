"""Command-line entry point: health check, KEV ingestion, one-shot ask, interactive chat."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from viper import __version__
from viper.config import Settings, get_settings
from viper.llm import LLMError, OllamaClient
from viper.logging_setup import configure_logging
from viper.rag import Answer, IngestError, answer, ingest
from viper.rag.backend import active_collection, open_registry, open_store
from viper.rag.cisa_kev import fetch_kev, parse_kev
from viper.rag.embedding import PrefixEmbedder
from viper.rag.types import Store

log = logging.getLogger("viper.cli")


def _build(settings: Settings) -> tuple[OllamaClient, Store]:
    llm = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    store = open_store(settings, active_collection(settings))
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


def cmd_kb(settings: Settings, args: argparse.Namespace) -> int:
    from viper.eval.cases import load_retrieval
    from viper.eval.retrieval import evaluate_retrieval
    from viper.rag.sources import all_sources
    from viper.rag.update import collect, run_update

    reg = open_registry(settings)
    if args.kb_cmd == "status":
        print(json.dumps({"active": reg.active or f"(default) kb_{settings.kb_version}",
                          "previous": reg.previous, "history": reg.history[-5:]}, indent=1))
        return 0
    if args.kb_cmd == "rollback":
        try:
            print(f"Rolled back. Active collection is now {reg.rollback()}.")
        except ValueError as exc:
            print(f"Rollback failed: {exc}", file=sys.stderr)
            return 1
        return 0

    reg.bootstrap(active_collection(settings))
    llm = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    qembed = PrefixEmbedder(llm, settings.embed_query_prefix)
    base = open_store(settings, reg.active or "")
    active = base
    staging = base.view(f"kb_{settings.kb_version}_{datetime.now(UTC):%Y%m%d%H%M%S}")
    cases = load_retrieval()

    def recall(store: Store) -> float:
        return float(evaluate_retrieval(cases, qembed, store)["overall"]["recall@4"])

    try:
        sources = all_sources()
        docs, outcomes = collect(sources, active)  # a failed source keeps its live records
        report = run_update(
            source="+".join(s.name for s in sources), docs=docs, outcomes=outcomes,
            doc_embedder=PrefixEmbedder(llm, settings.embed_doc_prefix),
            active=active, staging=staging, recall_at_4=recall,
            min_recall=settings.kb_min_recall_at_4, max_shrink=settings.kb_max_shrink,
            promote=None if args.no_promote else reg.promote,
        )
        if report.promoted:
            keep = {reg.active, reg.previous}
            for h in reg.history:  # prune superseded collections this tool created
                if h["event"] == "promote" and h["collection"] not in keep:
                    base.view(h["collection"]).drop()
    except (IngestError, LLMError) as exc:
        print(f"Update failed (live index untouched): {exc}", file=sys.stderr)
        return 1
    finally:
        base.close()
    out = Path("data/kb_reports")
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{report.started[:19].replace(':', '')}-{report.source}.json"
    path.write_text(json.dumps(report.to_dict(), indent=1), encoding="utf-8", newline="\n")
    print(json.dumps(report.to_dict(), indent=1))
    print(f"Report saved: {path}")
    return 0 if report.promoted or args.no_promote else 2


def cmd_eval(settings: Settings, args: argparse.Namespace) -> int:
    from viper.eval import runner
    from viper.eval.build import build

    if args.eval_cmd == "build":
        store = open_store(settings, active_collection(settings))
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
    report = runner.run_eval(
        settings, args.tag, skip_llm=args.skip_llm, only=only, dataset_version=args.dataset
    )
    path = runner.save_report(report)
    print(json.dumps({"retrieval": report["retrieval"]["overall"],
                      "calibration": report["retrieval"]["calibration"],
                      "answers": report.get("answers", {}).get("summary")}, indent=1))
    print(f"Report saved: {path}")
    return 0


def cmd_agent(settings: Settings, args: argparse.Namespace) -> int:
    from viper.agents import runner

    scope_path = Path(args.scope)
    try:
        if args.agent_cmd == "run":
            actions = runner.load_plan(Path(args.plan))
            out = runner.run(settings, scope_path, actions, args.request, args.thread)
        else:
            # Show exactly what is being decided, read from the saved checkpoint.
            for p in runner.pending_details(settings, scope_path, args.thread):
                act = p.get("action") or {}
                print(f"{args.decision} -> action {p['action_id']}: tool={act.get('tool_name')} "
                      f"args={json.dumps(act.get('args'), sort_keys=True)} "
                      f"hash={p['action_hash'][:12]} expires={p['expires_at']}")
            out = runner.resume(settings, scope_path, args.thread, args.decision)
    except Exception as exc:  # noqa: BLE001 - report class only; never echo details
        print(f"agent error: {type(exc).__name__}")
        return 1
    if out.get("__interrupt__"):
        print("PAUSED: approval needed. Resume with: "
              f"viper agent resume --scope <file> --thread {args.thread} --decision ALLOW|DENY")
        return 0
    print(out.get("report", out.get("status", "")))
    return 1 if out.get("status") == "FAILED" else 0


def cmd_audit(settings: Settings, args: argparse.Namespace) -> int:
    from viper.agents.audit import verify

    path = settings.audit_dir / f"{args.project}.jsonl"
    try:
        broken = verify(path)
    except Exception as exc:  # noqa: BLE001
        print(f"audit error: {type(exc).__name__}")
        return 1
    print("audit log OK" if broken is None else f"audit log BROKEN at seq {broken}")
    return 0 if broken is None else 2


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
    p_run.add_argument(
        "--dataset", choices=("v1", "v2"), default="v1",
        help="dataset version: v1 (default) or v2 (KEV + ATT&CK + OWASP)",
    )
    p_run.add_argument("--skip-llm", action="store_true", help="retrieval metrics only (fast)")
    p_run.add_argument("--only", default=None, help="comma list of case ids or categories")
    p_cmp = esub.add_parser("compare", help="compare two saved reports")
    p_cmp.add_argument("a")
    p_cmp.add_argument("b")
    p_kb = sub.add_parser("kb", help="knowledge-base lifecycle (safe weekly update)")
    ksub = p_kb.add_subparsers(dest="kb_cmd", required=True)
    p_upd = ksub.add_parser("update", help="fetch all sources (KEV, ATT&CK, OWASP), stage, gate and promote")
    p_upd.add_argument("--no-promote", action="store_true", help="stage and gate only (dry run)")
    ksub.add_parser("status", help="show the live collection and history")
    ksub.add_parser("rollback", help="point back at the previous collection")
    p_agent = sub.add_parser("agent", help="dry-run agent with policy and human approvals (M5)")
    asub = p_agent.add_subparsers(dest="agent_cmd", required=True)
    for name in ("run", "resume"):
        p = asub.add_parser(name)
        p.add_argument("--scope", required=True, help="scope YAML file")
        p.add_argument("--thread", required=True)
        if name == "run":
            p.add_argument("--plan", required=True, help="JSON list of proposed actions (planner stand-in)")
            p.add_argument("--request", default="")
        else:
            p.add_argument("--decision", choices=("ALLOW", "DENY"), required=True)
    p_audit = sub.add_parser("audit", help="audit log tools")
    usub = p_audit.add_subparsers(dest="audit_cmd", required=True)
    p_ver = usub.add_parser("verify", help="check the hash chain of a project log")
    p_ver.add_argument("--project", required=True)
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level)

    if args.health:
        log.info("health check", extra={"version": __version__})
        print(json.dumps({"status": "OK", "version": __version__, "config": settings.redacted()}, indent=2))
        return 0
    if args.command == "ingest-kev":
        return cmd_ingest_kev(settings, args.limit)
    if args.command == "kb":
        return cmd_kb(settings, args)
    if args.command == "eval":
        return cmd_eval(settings, args)
    if args.command == "agent":
        return cmd_agent(settings, args)
    if args.command == "audit":
        return cmd_audit(settings, args)
    if args.command == "chat":
        return cmd_ask(settings, args.question)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
