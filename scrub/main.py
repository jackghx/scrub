"""
main.py - Scrub's local FastAPI service
=======================================

Four endpoints, everything in-process, **no external calls in the scrub path**:

* ``POST /scrub``    ``{"text": str}``              -> ``{scrubbed, mapping, detections}``
* ``POST /restore``  ``{"text": str, "mapping": {}}`` -> ``{"original": str}``
* ``GET  /entities`` -> the entity types the pack can produce
* ``GET  /health``   -> ``{"status": "ok"}``

Run it locally::

    uvicorn main:app --host 127.0.0.1 --port 8000

It binds to localhost only by design, Scrub's whole point is that the data never
leaves the machine. Do not expose it via port-forwarding. (If you ever want remote
access, front it with an authenticated tunnel; never open a router port.)

The service defaults to custom-recognisers-only mode, so it starts with no spaCy
model. Set ``SCRUB_USE_NLP=1`` (and install a model) to enable full Presidio.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scrubber import Scrubber

app = FastAPI(
    title="Scrub",
    description="Local-first security-artefact sanitiser. Data never leaves the machine.",
    version="0.2.0",
)

# The review UI runs on localhost:3000 and this API on :8000, a cross-origin pair,
# so the browser needs an explicit CORS allowance to call us. Allow ONLY the local
# dev origins. This must never be broadened beyond localhost: the whole pitch is that
# the data never leaves the machine, and a permissive CORS policy would let any web
# page the user visits talk to their local scrubber.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# One Scrubber for the process lifetime. Custom-only by default; opt into full
# Presidio with SCRUB_USE_NLP=1 (requires a spaCy model, see README).
_use_nlp = os.environ.get("SCRUB_USE_NLP", "").lower() in {"1", "true", "yes"}
scrubber = Scrubber(use_nlp_engine=_use_nlp)


# --- request / response models ---------------------------------------------


class ScrubRequest(BaseModel):
    text: str = Field(..., description="Raw artefact to scrub.")


class Detection(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    placeholder: str
    original: str


class ScrubResponse(BaseModel):
    scrubbed: str
    mapping: Dict[str, str]
    detections: List[Detection]


class RestoreRequest(BaseModel):
    text: str = Field(..., description="Scrubbed text to reconstruct.")
    mapping: Dict[str, str] = Field(
        ..., description="The {placeholder: original} mapping returned by /scrub."
    )


class RestoreResponse(BaseModel):
    original: str


# --- endpoints --------------------------------------------------------------


@app.post("/scrub", response_model=ScrubResponse)
def scrub(req: ScrubRequest) -> Dict[str, Any]:
    """Detect + consistently pseudonymise. Returns the full detections list so a
    UI can show a diff and let the user toggle detections before exporting."""
    result = scrubber.scrub(req.text)
    return {
        "scrubbed": result.scrubbed_text,
        "mapping": result.mapping,
        "detections": result.detections,
    }


@app.post("/restore", response_model=RestoreResponse)
def restore(req: RestoreRequest) -> Dict[str, str]:
    """Reconstruct the original text from scrubbed text + mapping."""
    return {"original": scrubber.restore(req.text, req.mapping)}


@app.get("/entities")
def entities() -> Dict[str, List[str]]:
    """The entity types the security pack can produce."""
    return {"entities": scrubber.entities()}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "mode": "full" if scrubber.use_nlp_engine else "custom-only"}
