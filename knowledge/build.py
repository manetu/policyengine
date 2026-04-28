"""
knowledge/build.py — Pipeline to build the MPE knowledge artifact.

Stages (called in order by main()):
  1. chunk   — walk docs/docs/ and split into chunks  -> knowledge/target/chunks.jsonl
  2. embed   — encode chunks via Ollama               -> knowledge/target/vectors.bin
  3. lexical — build BM25 index                       -> knowledge/target/lexical-index.bin
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import frontmatter  # python-frontmatter
import numpy as np
import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DOCS_ROOT = Path(__file__).parent.parent / "docs" / "docs"
TARGET_DIR = Path(__file__).parent / "target"
CHUNKS_FILE = TARGET_DIR / "chunks.jsonl"
VECTORS_FILE = TARGET_DIR / "vectors.bin"
LEXICAL_FILE = TARGET_DIR / "lexical-index.bin"

TOKEN_BUDGET = 500  # ~words before splitting within an H2 section

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
EMBED_MODEL = os.environ.get("MPE_OLLAMA_MODEL", "nomic-embed-text:v1.5")
EMBED_DIMS = 768
EMBED_BATCH_SIZE = 4
EMBED_DOC_PREFIX = "search_document: "
EMBED_QUERY_PREFIX = "search_query: "
# Character limit per input (prefix + text).
# nomic-embed-text's GGUF architecture is capped at 2048 positions; num_ctx:8192 applies
# RoPE scaling that extends this slightly (~2100-2200 effective tokens) but not to 8192.
# Empirically: 5187 chars passes, 6346 fails (density ~2.4 chars/token for dense MDX/YAML).
# 5000 chars keeps us safely below the observed limit for all doc content types.
EMBED_MAX_INPUT_CHARS = 5000

BM25_K1 = 1.2
BM25_B = 0.75


# ---------------------------------------------------------------------------
# Chunker
# ---------------------------------------------------------------------------


def _word_count(text: str) -> int:
    return len(text.split())


def _chunk_id(path: str, heading_path: list[str], text: str) -> str:
    raw = path + "|" + "|".join(heading_path) + "|" + text
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _split_at_code_fences(
    section_lines: list[str],
    token_budget: int,
    fence_char_budget: int = 4000,
) -> list[list[str]]:
    """
    Split a list of lines into sub-chunks at code-fence boundaries when the
    accumulated word count exceeds token_budget.

    For fenced blocks that are themselves over budget, also splits at blank
    lines within the fence.  Uses character count (fence_char_budget) rather
    than word count for fence-internal splits because fenced code (YAML, etc.)
    has much higher chars-per-word density than prose.  Each continuation
    chunk reopens the original fence marker (e.g. "```yaml") so every
    sub-chunk is syntactically valid and carries the language hint.
    """
    chunks: list[list[str]] = []
    current: list[str] = []
    current_words = 0
    current_chars = 0
    in_fence = False
    fence_open_line: str = "```\n"

    for line in section_lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if not in_fence:
                in_fence = True
                fence_open_line = line
            else:
                in_fence = False

        current.append(line)
        current_words += _word_count(line)
        current_chars += len(line)

        if in_fence:
            if stripped == "" and current_chars >= fence_char_budget:
                # Over char budget inside a fence at a blank line — synthetic split
                current.append("```\n")
                chunks.append(current)
                current = [fence_open_line]
                current_words = _word_count(fence_open_line)
                current_chars = len(fence_open_line)
        elif current_words >= token_budget or current_chars >= fence_char_budget:
            # Outside a fence: flush on word-budget OR char-budget (the latter
            # catches YAML-heavy sections where words are sparse but chars are not)
            chunks.append(current)
            current = []
            current_words = 0
            current_chars = 0

    if current:
        chunks.append(current)

    return chunks


def chunk_documents(docs_root: Path, token_budget: int = TOKEN_BUDGET) -> list[dict[str, Any]]:
    """
    Walk all .md files under docs_root, parse frontmatter, split at H2
    boundaries (and code-fence sub-boundaries when needed), and return a list
    of chunk dicts with keys: id, path, heading_path, frontmatter, text.
    """
    chunks: list[dict[str, Any]] = []
    docs_root = Path(docs_root)

    md_files = sorted(docs_root.rglob("*.md"))  # sorted for determinism

    for md_path in md_files:
        post = frontmatter.load(str(md_path))
        fm: dict[str, Any] = dict(post.metadata)
        body: str = post.content

        rel_path = str(md_path.relative_to(docs_root.parent.parent))  # docs/docs/…

        lines = body.splitlines(keepends=True)

        # Collect H1 title (first # heading in the doc)
        h1_title: str | None = None
        for line in lines:
            m = re.match(r"^#\s+(.+)", line)
            if m:
                h1_title = m.group(1).strip()
                break

        # Split into H2 sections -----------------------------------------
        # Each section: (h2_title, [lines])
        sections: list[tuple[str | None, list[str]]] = []
        current_h2: str | None = None
        current_lines: list[str] = []

        for line in lines:
            m = re.match(r"^##\s+(.+)", line)
            if m:
                # Save previous section
                if current_lines or current_h2 is not None:
                    sections.append((current_h2, current_lines))
                current_h2 = m.group(1).strip()
                current_lines = [line]
            else:
                current_lines.append(line)

        # Flush last section
        if current_lines or current_h2 is not None:
            sections.append((current_h2, current_lines))

        # If no H2 sections found, treat the whole body as one chunk
        if not sections:
            sections = [(None, lines)]

        # Build chunks from sections -------------------------------------
        for h2_title, sec_lines in sections:
            heading_path: list[str] = []
            if h1_title:
                heading_path.append(h1_title)
            if h2_title:
                heading_path.append(h2_title)

            text = "".join(sec_lines).strip()
            if not text:
                continue

            if _word_count(text) <= token_budget:
                sub_chunks = [sec_lines]
            else:
                sub_chunks = _split_at_code_fences(sec_lines, token_budget)

            for sub in sub_chunks:
                sub_text = "".join(sub).strip()
                if not sub_text:
                    continue
                chunk: dict[str, Any] = {
                    "id": _chunk_id(rel_path, heading_path, sub_text),
                    "path": rel_path,
                    "heading_path": heading_path,
                    "frontmatter": fm,
                    "text": sub_text,
                }
                chunks.append(chunk)

    return chunks


# ---------------------------------------------------------------------------
# Embedder
# ---------------------------------------------------------------------------


def embed_chunks(chunks: list[dict[str, Any]], batch_size: int = EMBED_BATCH_SIZE) -> np.ndarray:
    """
    Encode each chunk's text via Ollama and return a (len(chunks), EMBED_DIMS)
    float32 array in chunks.jsonl order.

    Batches are submitted sequentially (no concurrency) to preserve row order.
    Transient/5xx errors are retried up to 3 times; 4xx errors fail immediately.
    """
    # nomic-embed-text requires a task prefix on document texts at index time;
    # the matching query prefix is stored in the manifest for consumers.
    texts = []
    for chunk in chunks:
        t = EMBED_DOC_PREFIX + chunk["text"]
        if len(t) > EMBED_MAX_INPUT_CHARS:
            print(
                f"  Warning: truncating chunk from {len(t)} to {EMBED_MAX_INPUT_CHARS} chars"
                f" ({chunk['path']} {chunk['heading_path']})",
                file=sys.stderr,
            )
            t = t[:EMBED_MAX_INPUT_CHARS]
        texts.append(t)
    n = len(texts)
    out = np.empty((n, EMBED_DIMS), dtype=np.float32)
    url = f"{OLLAMA_HOST}/api/embed"

    print(f"Embedding {n} chunks via {OLLAMA_HOST} (model={EMBED_MODEL}, batch_size={batch_size}) ...")
    t0 = time.monotonic()

    with requests.Session() as session:
        for i in range(0, n, batch_size):
            batch = texts[i : i + batch_size]
            last_err: Exception | None = None
            for attempt in range(3):
                try:
                    resp = session.post(
                        url,
                        json={
                            "model": EMBED_MODEL,
                            "input": batch,
                            # Use the full 8192-token capacity of nomic-embed-text.
                            "options": {"num_ctx": 8192},
                        },
                        timeout=300,
                    )
                    if resp.status_code >= 400:
                        raise requests.HTTPError(
                            f"ollama {resp.status_code} at chunk offset {i}: {resp.text[:400]}"
                        )
                    embs = resp.json().get("embeddings")
                    if not isinstance(embs, list) or len(embs) != len(batch):
                        raise RuntimeError(
                            f"expected {len(batch)} embeddings, got "
                            f"{len(embs) if isinstance(embs, list) else type(embs).__name__!r}"
                        )
                    arr = np.asarray(embs, dtype=np.float32)
                    if arr.shape != (len(batch), EMBED_DIMS):
                        raise AssertionError(f"shape mismatch at offset {i}: {arr.shape}")
                    out[i : i + len(batch)] = arr
                    last_err = None
                    break
                except (requests.RequestException, RuntimeError, AssertionError) as e:
                    last_err = e
                    if attempt < 2:
                        time.sleep(1.5**attempt)
            if last_err is not None:
                raise RuntimeError(f"ollama embed failed after retries: {last_err}") from last_err
            if ((i // batch_size) + 1) % 5 == 0 or i + len(batch) >= n:
                print(f"  {i + len(batch)}/{n}")

    elapsed = time.monotonic() - t0
    throughput = n / elapsed if elapsed > 0 else float("inf")
    print(f"Embedded {n} chunks in {elapsed:.1f}s ({throughput:.1f} chunks/sec)")
    return out


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------


def run_chunk(docs_root: Path = DOCS_ROOT) -> list[dict[str, Any]]:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    chunks = chunk_documents(docs_root)
    with CHUNKS_FILE.open("w", encoding="utf-8") as fh:
        for chunk in chunks:
            fh.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    print(f"Chunked {len(chunks)} chunks -> {CHUNKS_FILE}")
    return chunks


def run_embed(batch_size: int = EMBED_BATCH_SIZE) -> np.ndarray:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    if not CHUNKS_FILE.exists():
        print(f"ERROR: {CHUNKS_FILE} not found — run --stage=chunk first", file=sys.stderr)
        sys.exit(1)

    with CHUNKS_FILE.open("r", encoding="utf-8") as fh:
        chunks = [json.loads(line) for line in fh if line.strip()]

    vectors = embed_chunks(chunks, batch_size=batch_size)

    expected_bytes = len(chunks) * EMBED_DIMS * 4
    raw = vectors.astype("<f4").tobytes()  # little-endian float32
    assert len(raw) == expected_bytes, (
        f"Expected {expected_bytes} bytes, got {len(raw)}"
    )

    VECTORS_FILE.write_bytes(raw)
    print(f"Wrote {len(raw):,} bytes -> {VECTORS_FILE}")
    return vectors


# ---------------------------------------------------------------------------
# BM25 lexical index
# ---------------------------------------------------------------------------

_BM25_MAGIC = b"BM25"
_BM25_VERSION = 1


def build_lexical_index(chunks: list[dict[str, Any]]) -> bytes:
    """
    Build a BM25Okapi index over chunk texts and serialize to a binary format.

    Binary layout (all integers/floats little-endian):

    Header (16 bytes):
      magic      4 bytes  b"BM25"
      version    2 bytes  uint16, value=1
      k1         4 bytes  float32
      b          4 bytes  float32
      reserved   2 bytes  zeros

    Vocabulary section:
      vocab_size  4 bytes  uint32  — number of unique terms
      (repeated vocab_size times):
        term_len  2 bytes  uint16  — UTF-8 byte length of term
        term      N bytes  UTF-8
        idf       4 bytes  float32

    Postings section (same term order as vocabulary):
      (repeated vocab_size times):
        posting_count  4 bytes  uint32
        (repeated posting_count times):
          chunk_id   4 bytes  uint32   — 0-based index into chunks.jsonl
          tf_score   4 bytes  float32  — freq*(k1+1)/(freq+k1*(1-b+b*|d|/avgdl))

    Terms are sorted alphabetically; postings are sorted by ascending chunk_id.
    Tokenization: chunk["text"].lower().split()
    """
    from rank_bm25 import BM25Okapi  # lazy import

    tokenized = [chunk["text"].lower().split() for chunk in chunks]
    bm25 = BM25Okapi(tokenized, k1=BM25_K1, b=BM25_B)

    k1 = bm25.k1
    b_val = bm25.b
    avgdl = bm25.avgdl

    # Sort vocabulary for determinism
    vocab = sorted(bm25.idf.keys())

    # Build posting lists: term -> [(chunk_id, tf_score)]
    postings: dict[str, list[tuple[int, float]]] = {term: [] for term in vocab}
    for chunk_idx, doc_freqs in enumerate(bm25.doc_freqs):
        doc_len = bm25.doc_len[chunk_idx]
        norm = k1 * (1.0 - b_val + b_val * doc_len / avgdl)
        for term, freq in doc_freqs.items():
            tf_score = float(freq) * (k1 + 1.0) / (float(freq) + norm)
            postings[term].append((chunk_idx, tf_score))

    # Sort each posting list by chunk_id for determinism
    for term in vocab:
        postings[term].sort(key=lambda x: x[0])

    # Serialize
    buf = bytearray()

    # Header
    buf += _BM25_MAGIC
    buf += struct.pack("<H", _BM25_VERSION)
    buf += struct.pack("<f", k1)
    buf += struct.pack("<f", b_val)
    buf += b"\x00\x00"  # reserved

    # Vocabulary
    buf += struct.pack("<I", len(vocab))
    for term in vocab:
        term_bytes = term.encode("utf-8")
        buf += struct.pack("<H", len(term_bytes))
        buf += term_bytes
        buf += struct.pack("<f", float(bm25.idf[term]))

    # Postings (same order as vocabulary)
    for term in vocab:
        pl = postings[term]
        buf += struct.pack("<I", len(pl))
        for chunk_id, tf_score in pl:
            buf += struct.pack("<I", chunk_id)
            buf += struct.pack("<f", tf_score)

    return bytes(buf)


def _deserialize_lexical_index(
    data: bytes,
) -> tuple[float, float, dict[str, float], dict[str, list[tuple[int, float]]]]:
    """
    Deserialize a lexical-index.bin produced by build_lexical_index().

    Returns (k1, b, idf_dict, postings_dict) where:
      idf_dict:      term -> idf float
      postings_dict: term -> [(chunk_id, tf_score), ...]
    """
    offset = 0

    magic = data[offset : offset + 4]
    if magic != _BM25_MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    offset += 4

    (version,) = struct.unpack_from("<H", data, offset)
    offset += 2
    if version != _BM25_VERSION:
        raise ValueError(f"Unsupported version: {version}")

    (k1,) = struct.unpack_from("<f", data, offset)
    offset += 4
    (b,) = struct.unpack_from("<f", data, offset)
    offset += 4
    offset += 2  # reserved

    (vocab_size,) = struct.unpack_from("<I", data, offset)
    offset += 4

    terms: list[str] = []
    idf_dict: dict[str, float] = {}
    for _ in range(vocab_size):
        (term_len,) = struct.unpack_from("<H", data, offset)
        offset += 2
        term = data[offset : offset + term_len].decode("utf-8")
        offset += term_len
        (idf,) = struct.unpack_from("<f", data, offset)
        offset += 4
        terms.append(term)
        idf_dict[term] = idf

    postings_dict: dict[str, list[tuple[int, float]]] = {}
    for term in terms:
        (count,) = struct.unpack_from("<I", data, offset)
        offset += 4
        pl: list[tuple[int, float]] = []
        for _ in range(count):
            (chunk_id,) = struct.unpack_from("<I", data, offset)
            offset += 4
            (tf,) = struct.unpack_from("<f", data, offset)
            offset += 4
            pl.append((chunk_id, tf))
        postings_dict[term] = pl

    if offset != len(data):
        raise ValueError(f"Trailing bytes: expected offset {len(data)}, got {offset}")

    return k1, b, idf_dict, postings_dict


def _test_lexical_round_trip(data: bytes) -> None:
    """Deserialize data and assert basic structural invariants."""
    k1, b, idf_dict, postings_dict = _deserialize_lexical_index(data)

    assert abs(k1 - BM25_K1) < 1e-5, f"k1 mismatch: {k1}"
    assert abs(b - BM25_B) < 1e-5, f"b mismatch: {b}"
    assert len(idf_dict) == len(postings_dict), "vocab/postings length mismatch"

    if idf_dict:
        term = next(iter(idf_dict))
        assert isinstance(idf_dict[term], float), "IDF not a float"
        pl = postings_dict[term]
        if pl:
            chunk_id, tf = pl[0]
            assert isinstance(chunk_id, int), "chunk_id not an int"
            assert isinstance(tf, float), "tf_score not a float"
            assert tf > 0.0, "tf_score should be positive"

    print(f"Round-trip test passed: {len(idf_dict)} terms, k1={k1}, b={b}")


def _get_model_digest() -> str:
    """Return the digest reported by Ollama for EMBED_MODEL, or 'unknown' on failure."""
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=30)
        resp.raise_for_status()
        for model in resp.json().get("models", []):
            if model.get("name") == EMBED_MODEL:
                digest = model.get("digest", "")
                return f"sha256:{digest}" if digest else "unknown"
        return "unknown"
    except Exception as exc:
        print(f"Warning: could not retrieve model digest: {exc}", file=sys.stderr)
        return "unknown"


def run_assemble() -> Path:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    # Validate prerequisites
    for f in (CHUNKS_FILE, VECTORS_FILE, LEXICAL_FILE):
        if not f.exists():
            print(f"ERROR: {f} not found — run earlier stages first", file=sys.stderr)
            sys.exit(1)

    curated_file = Path(__file__).parent / "curated_baseline.md"
    pom_file = Path(__file__).parent / "pom.xml"
    for f in (curated_file, pom_file):
        if not f.exists():
            print(f"ERROR: {f} not found", file=sys.stderr)
            sys.exit(1)

    # Count chunks
    with CHUNKS_FILE.open("r", encoding="utf-8") as fh:
        chunk_count = sum(1 for line in fh if line.strip())

    # Validate vectors.bin size
    vectors_size = VECTORS_FILE.stat().st_size
    expected_size = chunk_count * EMBED_DIMS * 4
    if vectors_size != expected_size:
        print(
            f"ERROR: vectors.bin size {vectors_size} != expected {expected_size} "
            f"({chunk_count} chunks × {EMBED_DIMS} dims × 4 bytes)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Determine version from git
    try:
        version = subprocess.check_output(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=Path(__file__).parent.parent,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        version = "dev"

    # Get doc commit sha
    try:
        doc_commit_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).parent.parent,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        doc_commit_sha = "unknown"

    # Build manifest
    manifest = {
        "manifest_version": 1,
        "mpe_version": version,
        "embed_model": EMBED_MODEL,
        "embed_model_digest": _get_model_digest(),
        "embed_dims": EMBED_DIMS,
        "embed_query_prefix": EMBED_QUERY_PREFIX,
        "chunk_count": chunk_count,
        "build_timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "doc_commit_sha": doc_commit_sha,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    jar_path = TARGET_DIR / f"mpe-knowledge-{version}.jar"

    with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.write(curated_file, "curated_baseline.md")
        zf.write(CHUNKS_FILE, "chunks.jsonl")
        zf.write(VECTORS_FILE, "vectors.bin")
        zf.write(LEXICAL_FILE, "lexical-index.bin")
        zf.write(pom_file, "META-INF/maven/com.manetu/mpe-knowledge/pom.xml")

    # Compute sha256 over sorted entry contents (deterministic, excludes timestamps)
    h = hashlib.sha256()
    with zipfile.ZipFile(jar_path, "r") as zf:
        for name in sorted(zf.namelist()):
            h.update(zf.read(name))
    fingerprint = h.hexdigest()

    jar_name = jar_path.name
    print(f"sha256: {fingerprint}  {jar_name}")
    print(f"Assembled {jar_path} ({jar_path.stat().st_size:,} bytes)")
    return jar_path


def run_lexical() -> bytes:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    if not CHUNKS_FILE.exists():
        print(f"ERROR: {CHUNKS_FILE} not found — run --stage=chunk first", file=sys.stderr)
        sys.exit(1)

    with CHUNKS_FILE.open("r", encoding="utf-8") as fh:
        chunks = [json.loads(line) for line in fh if line.strip()]

    print(f"Building BM25 index over {len(chunks)} chunks (k1={BM25_K1}, b={BM25_B}) ...")
    t0 = time.monotonic()
    data = build_lexical_index(chunks)
    elapsed = time.monotonic() - t0

    _test_lexical_round_trip(data)

    LEXICAL_FILE.write_bytes(data)
    print(f"Wrote {len(data):,} bytes -> {LEXICAL_FILE} ({elapsed:.2f}s)")
    return data


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Build MPE knowledge artifact")
    parser.add_argument(
        "--stage",
        choices=["chunk", "embed", "lexical", "assemble", "all"],
        default="all",
        help="Pipeline stage to run (default: all)",
    )
    parser.add_argument(
        "--docs-root",
        type=Path,
        default=DOCS_ROOT,
        help=f"Path to docs root (default: {DOCS_ROOT})",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=EMBED_BATCH_SIZE,
        help=f"Embedding batch size (default: {EMBED_BATCH_SIZE})",
    )
    args = parser.parse_args()

    if args.stage in ("chunk", "all"):
        run_chunk(docs_root=args.docs_root)

    if args.stage in ("embed", "all"):
        run_embed(batch_size=args.batch_size)

    if args.stage in ("lexical", "all"):
        run_lexical()

    if args.stage in ("assemble", "all"):
        run_assemble()


if __name__ == "__main__":
    main()
