#!/usr/bin/env python3
"""Simple MITRE ATT&CK question-answer bot for local CSV/XLSX datasets."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import pandas as pd

CORE_SHEETS = [
    "techniques",
    "tactics",
    "software",
    "groups",
    "campaigns",
    "mitigations",
]


@dataclass
class Result:
    score: int
    sheet: str
    row: dict


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).strip().lower())


def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]{2,}", normalize(text))


def load_data(path: Path) -> Dict[str, pd.DataFrame]:
    if not path.exists():
        raise FileNotFoundError(f"Data file not found: {path}")

    suffix = path.suffix.lower()
    frames: Dict[str, pd.DataFrame] = {}

    if suffix == ".csv":
        # CSV mode: query one flat table as techniques.
        frame = pd.read_csv(path)
        frames["techniques"] = frame.fillna("")
        return frames

    if suffix in {".xlsx", ".xlsm", ".xls"}:
        workbook = pd.ExcelFile(path)
        available = set(workbook.sheet_names)
        for sheet in CORE_SHEETS:
            if sheet in available:
                frames[sheet] = pd.read_excel(path, sheet_name=sheet).fillna("")
        if not frames:
            raise ValueError("No expected MITRE sheets found in workbook")
        return frames

    raise ValueError("Unsupported file type. Use CSV or XLSX")


def build_query_text(row: dict) -> str:
    parts = [
        row.get("ID", ""),
        row.get("name", ""),
        row.get("description", ""),
        row.get("tactics", ""),
        row.get("aliases", ""),
        row.get("platforms", ""),
        row.get("type", ""),
    ]
    return " ".join(str(p) for p in parts if p)


def row_score(question: str, row: dict) -> int:
    question_tokens = tokenize(question)
    blob = normalize(build_query_text(row))

    score = 0
    for token in question_tokens:
        if token in blob:
            score += 2

    id_value = str(row.get("ID", ""))
    name_value = str(row.get("name", ""))

    if id_value and normalize(id_value) in normalize(question):
        score += 30
    if name_value and normalize(name_value) in normalize(question):
        score += 12

    return score


def search(question: str, frames: Dict[str, pd.DataFrame], top_k: int = 5) -> List[Result]:
    results: List[Result] = []

    for sheet, frame in frames.items():
        for _, r in frame.iterrows():
            row = r.to_dict()
            score = row_score(question, row)
            if score > 0:
                results.append(Result(score=score, sheet=sheet, row=row))

    results.sort(key=lambda x: x.score, reverse=True)
    return results[:top_k]


def format_result(result: Result) -> str:
    row = result.row
    attack_id = str(row.get("ID", "")).strip()
    name = str(row.get("name", "")).strip()
    description = str(row.get("description", "")).strip().replace("\n", " ")
    url = str(row.get("url", "")).strip()

    short_desc = description[:420] + ("..." if len(description) > 420 else "")

    lines = [
        f"[{result.sheet}] {attack_id} - {name}",
        f"Score: {result.score}",
    ]

    if row.get("tactics", ""):
        lines.append(f"Tactics: {row.get('tactics')}")
    if row.get("platforms", ""):
        lines.append(f"Platforms: {row.get('platforms')}")
    if short_desc:
        lines.append(f"Description: {short_desc}")
    if url:
        lines.append(f"URL: {url}")

    return "\n".join(lines)


def chat_loop(frames: Dict[str, pd.DataFrame]) -> None:
    print("MITRE Agent ready. Ask about ATT&CK techniques, tactics, groups, software, or mitigations.")
    print("Examples: 'What is T1059?', 'credential access tactics', 'APT29 software'")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            question = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return

        if not question:
            continue
        if question.lower() in {"exit", "quit", "q"}:
            print("Goodbye.")
            return

        matches = search(question, frames)
        if not matches:
            print("Bot> I couldn't find a strong match. Try adding an ATT&CK ID or more keywords.\n")
            continue

        print("Bot>")
        for i, match in enumerate(matches, start=1):
            print(f"\n{i}. {format_result(match)}")
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple MITRE ATT&CK local question-answer bot")
    parser.add_argument(
        "--data",
        default="enterprise-attack-v18.1.xlsx",
        help="Path to MITRE CSV/XLSX file (default: enterprise-attack-v18.1.xlsx)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data_path = Path(args.data)
    frames = load_data(data_path)
    chat_loop(frames)


if __name__ == "__main__":
    main()
