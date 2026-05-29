"""
pseudonymizer.py
================

Turn ``text`` + Presidio detections into scrubbed text with **stable,
human-readable placeholders**, and reverse the process exactly.

This is the ownable core of Scrub. General PII tools redact (``<REDACTED>``) and
throw the value away; that destroys the analytical usefulness of a log. Scrub
instead *pseudonymises consistently*: every occurrence of the same raw value gets
the same placeholder (``<INTERNAL_IP_1>``), so the scrubbed artefact still reads as
a coherent trace, you can follow which host talked to which, without leaking the
real identifiers. And because the mapping is kept, the original can be reconstructed
byte-for-byte.

Design points
-------------
* **Consistency**, a ``value -> placeholder`` table plus per-entity-type counters
  mean the same value always maps to the same placeholder, and distinct values of a
  type get ``_1``, ``_2``, … in order of first appearance.
* **Overlap resolution**, when detections overlap, the higher-scoring / longer span
  wins and the rest are dropped, so no character is substituted twice.
* **Right-to-left substitution**, spans are replaced in descending start order, so
  earlier offsets stay valid while later ones are rewritten.
* **No Presidio import**, this module only duck-types detections (anything with
  ``entity_type``, ``start``, ``end``, ``score``), so it is trivially unit-testable
  and stays decoupled from the detection layer.

Nothing here makes a network call. Local-first is the whole pitch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

DEFAULT_FMT = "<{entity}_{n}>"


@dataclass
class ScrubResult:
    """The output of a scrub.

    Attributes
    ----------
    scrubbed_text:
        ``text`` with every surviving detection replaced by its placeholder.
    mapping:
        ``{placeholder: original_value}``, everything :func:`restore` needs to
        reconstruct the original. Treat this as sensitive: it contains the raw
        secrets.
    detections:
        The detections that were actually applied, each as a dict with
        ``entity_type``, ``start``, ``end`` (offsets into the *original* text),
        ``score``, ``placeholder`` and ``original``. Returned in document order so
        a review-before-export UI can show a diff and let the user toggle
        individual detections off. (Detections dropped during overlap resolution
        are not included, they were never substituted.)
    """

    scrubbed_text: str
    mapping: Dict[str, str] = field(default_factory=dict)
    detections: List[Dict[str, Any]] = field(default_factory=list)


def _resolve_overlaps(results: Sequence[Any]) -> List[Any]:
    """Drop overlapping detections, keeping the strongest span.

    Ranking: higher ``score`` first, then longer span, then earlier ``start``.
    A detection is kept only if it does not overlap any already-kept span; this
    naturally drops a span fully contained inside another, as well as partial
    overlaps.
    """
    ordered = sorted(
        results,
        key=lambda r: (-float(r.score), -(r.end - r.start), r.start),
    )
    kept: List[Any] = []
    for cand in ordered:
        if any(cand.start < k.end and k.start < cand.end for k in kept):
            continue  # overlaps a stronger span already kept
        kept.append(cand)
    return kept


def pseudonymize(
    text: str,
    results: Sequence[Any],
    fmt: str = DEFAULT_FMT,
) -> ScrubResult:
    """Pseudonymise ``text`` using detection ``results``.

    Parameters
    ----------
    text:
        The original artefact.
    results:
        Detections, Presidio ``RecognizerResult`` objects, or anything exposing
        ``entity_type``, ``start``, ``end`` and ``score``.
    fmt:
        Placeholder template. Receives ``entity`` (the entity type) and ``n`` (the
        per-type counter, 1-based). Default ``"<{entity}_{n}>"``.

    Returns
    -------
    ScrubResult
    """
    if not results:
        # No-detections passthrough: original text, empty mapping.
        return ScrubResult(scrubbed_text=text, mapping={}, detections=[])

    kept = _resolve_overlaps(results)

    # Assign placeholders in order of first appearance (start ascending) so the
    # numbering reads naturally top-to-bottom.
    kept_by_position = sorted(kept, key=lambda r: (r.start, r.end))

    mapping: Dict[str, str] = {}            # placeholder -> original
    value_to_placeholder: Dict[tuple, str] = {}   # (entity_type, value) -> placeholder
    counters: Dict[str, int] = {}           # entity_type -> last index used
    detections: List[Dict[str, Any]] = []

    for det in kept_by_position:
        original = text[det.start : det.end]
        key = (det.entity_type, original)
        placeholder = value_to_placeholder.get(key)
        if placeholder is None:
            counters[det.entity_type] = counters.get(det.entity_type, 0) + 1
            placeholder = fmt.format(entity=det.entity_type, n=counters[det.entity_type])
            value_to_placeholder[key] = placeholder
            mapping[placeholder] = original
        detections.append(
            {
                "entity_type": det.entity_type,
                "start": det.start,
                "end": det.end,
                "score": float(det.score),
                "placeholder": placeholder,
                "original": original,
            }
        )

    # Substitute right-to-left so earlier offsets stay valid as we rewrite.
    scrubbed = text
    for det in sorted(detections, key=lambda d: d["start"], reverse=True):
        scrubbed = scrubbed[: det["start"]] + det["placeholder"] + scrubbed[det["end"] :]

    return ScrubResult(scrubbed_text=scrubbed, mapping=mapping, detections=detections)


def restore(scrubbed_text: str, mapping: Dict[str, str]) -> str:
    """Reconstruct the original text from scrubbed text + mapping.

    Replaces each placeholder with its original value. Placeholders are applied
    longest-first so that, under a custom ``fmt`` without a closing delimiter, a
    shorter placeholder (``X_1``) cannot clobber a longer one (``X_10``). With the
    default ``<...>`` format this is moot, but the guard is cheap.
    """
    restored = scrubbed_text
    for placeholder in sorted(mapping, key=len, reverse=True):
        restored = restored.replace(placeholder, mapping[placeholder])
    return restored


__all__ = ["ScrubResult", "pseudonymize", "restore", "DEFAULT_FMT"]
