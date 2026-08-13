"""Corpus card loader and markdown parser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


@dataclass(frozen=True)
class KnowledgeCard:
    """A single corpus document card."""

    id: str
    title: str
    tags: tuple[str, ...]
    summary: str
    body: str


def parse_card_file(file_path: Path) -> KnowledgeCard:
    """Parse front-matter YAML header and markdown body from a file."""
    text = file_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    metadata: dict[str, str] = {}
    body_lines: list[str] = []
    in_frontmatter = False

    for line in lines:
        if line.strip() == "---":
            if not in_frontmatter and not metadata:
                in_frontmatter = True
                continue
            elif in_frontmatter:
                in_frontmatter = False
                continue

        if in_frontmatter:
            if ":" in line:
                key, val = line.split(":", 1)
                metadata[key.strip()] = val.strip().strip("[]")
        else:
            body_lines.append(line)

    card_id = metadata.get("id", file_path.stem)
    title = metadata.get("title", file_path.stem.replace("_", " ").title())
    raw_tags = metadata.get("tags", "")
    tags = tuple(t.strip() for t in raw_tags.split(",") if t.strip())
    summary = metadata.get("summary", title)
    body = "\n".join(body_lines).strip()

    return KnowledgeCard(id=card_id, title=title, tags=tags, summary=summary, body=body)


def load_corpus() -> list[KnowledgeCard]:
    """Load all markdown files in the corpus directory."""
    if not CORPUS_DIR.is_dir():
        return []
    cards = []
    for file_path in CORPUS_DIR.glob("*.md"):
        try:
            cards.append(parse_card_file(file_path))
        except Exception:
            continue
    return cards
