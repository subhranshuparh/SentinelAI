"""BM25 retrieval engine with synonym expansion and score floor."""

from __future__ import annotations

import math
import re
from typing import Sequence

from app.services.assistant.cards import KnowledgeCard

STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he",
    "in", "is", "it", "its", "like", "of", "on", "or", "that", "the", "to",
    "was", "were", "what", "when", "where", "which", "who", "will", "with", "you",
    "your", "today"
}

#: Domain synonym expansion dictionary
SYNONYMS = {
    "otp": ["code", "one-time", "pin", "verification"],
    "upi": ["gpay", "phonepe", "paytm", "bhim", "collect", "payment"],
    "score": ["arithmetic", "posture", "overall", "rating", "drivers", "lever"],
    "password": ["breach", "pwned", "identity", "k-anonymity", "hash"],
    "aadhaar": ["pan", "pii", "verhoeff", "masking", "checksum"],
    "qr": ["scan", "debit", "code", "barcode"],
    "review": ["fake", "manipulated", "amazon", "rating", "jaccard"],
}

#: Relevance threshold: queries scoring below this return answered=False
RELEVANCE_FLOOR = 1.0


def tokenize_query(query: str) -> list[str]:
    """Tokenise, normalise, remove stop words, and expand synonyms."""
    words = [
        w for w in re.findall(r"\b[a-z0-9]{3,}\b", query.lower())
        if w not in STOP_WORDS
    ]
    tokens = list(words)
    for w in words:
        if w in SYNONYMS:
            tokens.extend(SYNONYMS[w])
    return tokens


def retrieve_cards(
    query: str, corpus: Sequence[KnowledgeCard], top_k: int = 3
) -> list[tuple[KnowledgeCard, float]]:
    """Retrieve top-k relevant knowledge cards using Okapi BM25 scoring."""
    raw_words = set(re.findall(r"\b[a-z]+\b", query.lower()))
    is_personal_query = any(w in ("my", "mine", "me", "i", "our") for w in raw_words)

    tokens = tokenize_query(query)
    if not tokens or not corpus:
        return []

    # BM25 parameters
    k1 = 1.5
    b = 0.75

    doc_tokens = [tokenize_query(f"{c.title} {c.summary} {c.body} {' '.join(c.tags)}") for c in corpus]
    doc_lens = [len(dt) for dt in doc_tokens]
    avg_len = sum(doc_lens) / len(doc_lens) if doc_lens else 1.0

    # Calculate DF
    df: dict[str, int] = {}
    for dt in doc_tokens:
        unique_tokens = set(dt)
        for t in unique_tokens:
            df[t] = df.get(t, 0) + 1

    num_docs = len(corpus)
    scores: list[tuple[KnowledgeCard, float]] = []

    for idx, card in enumerate(corpus):
        score = 0.0
        dt = doc_tokens[idx]
        d_len = doc_lens[idx]

        for token in tokens:
            tf = dt.count(token)
            if tf == 0:
                continue
            doc_freq = df.get(token, 0)
            idf = math.log((num_docs - doc_freq + 0.5) / (doc_freq + 0.5) + 1.0)
            denom = tf + k1 * (1.0 - b + b * (d_len / avg_len))
            score += idf * (tf * (k1 + 1.0) / denom)

        if is_personal_query and card.id.startswith("user_"):
            score += 50.0

        if score >= RELEVANCE_FLOOR:
            scores.append((card, score))

    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]
