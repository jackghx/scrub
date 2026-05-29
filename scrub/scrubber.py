"""
scrubber.py
===========

The ``Scrubber`` ties the detection layer (``security_recognizers``) to the
consistent pseudonymiser (``pseudonymizer``) behind one small surface:

    s = Scrubber()
    result = s.scrub(my_log)         # -> ScrubResult
    original = s.restore(result.scrubbed_text, result.mapping)

Two modes
---------
* **Custom pack only (default).** Runs the security recogniser pack directly with
  no NLP engine, so it needs **no spaCy model download**, clone and go. This is
  the project's bread and butter: internal IPs, hostnames, MACs, cloud keys,
  tokens, private keys, connection strings.
* **Full Presidio (opt-in, ``use_nlp_engine=True``).** Stands the pack on top of a
  real Presidio ``AnalyzerEngine`` so Presidio's *built-in* recognisers (PERSON,
  EMAIL_ADDRESS, etc.) fire too. This needs a spaCy model
  (``python -m spacy download en_core_web_lg``); if it is missing we fail with a
  clear, actionable message rather than a stack trace.

Either way **no network call happens in the scrub path**, that is a hard
constraint, not a preference.
"""

from __future__ import annotations

from typing import List

from context_enhancer import enhance_with_context
from pseudonymizer import ScrubResult, pseudonymize, restore
from security_recognizers import (
    get_security_recognizers,
    register_security_recognizers,
    supported_entities,
)

DEFAULT_MODEL = "en_core_web_lg"


class Scrubber:
    """Detect + consistently pseudonymise security artefacts.

    Parameters
    ----------
    use_nlp_engine:
        ``False`` (default), custom security pack only, no spaCy required.
        ``True``, full Presidio (pack + built-in PII recognisers); needs a model.
    language:
        Analysis language. Only meaningful in full mode.
    model:
        spaCy model name for full mode. Defaults to ``en_core_web_lg``.
    score_threshold:
        Minimum detection score to act on. Defaults to ``0.0``, i.e. scrub
        everything the pack flags. Recall is deliberately favoured over precision
        here: under-scrubbing leaks a secret, whereas an over-zealous detection is
        a false positive the user can toggle off in the returned ``detections``
        list before exporting. Raise this if you want fewer, higher-confidence
        substitutions.
    """

    def __init__(
        self,
        use_nlp_engine: bool = False,
        language: str = "en",
        model: str = DEFAULT_MODEL,
        score_threshold: float = 0.0,
    ) -> None:
        self.use_nlp_engine = use_nlp_engine
        self.language = language
        self.model = model
        self.score_threshold = score_threshold

        if use_nlp_engine:
            self._analyzer = self._build_full_analyzer(model, language)
            self._recognizers = None
        else:
            # Custom-only: hold one instance of each recogniser and run them
            # directly. This mirrors how the provided test harness exercises the
            # pack and needs no NLP engine / model.
            self._analyzer = None
            self._recognizers = get_security_recognizers()

    # -- construction helpers ------------------------------------------------

    @staticmethod
    def _build_full_analyzer(model: str, language: str):
        """Build a Presidio AnalyzerEngine backed by a spaCy model, with the
        security pack registered. Raises a clear error if the model is absent."""
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": model}],
            }
        )
        try:
            nlp_engine = provider.create_engine()
        except Exception as exc:  # OSError when the model isn't installed
            raise RuntimeError(
                f"Full mode needs the spaCy model '{model}', which isn't installed.\n"
                f"Install it with:\n\n"
                f"    python -m spacy download {model}\n\n"
                f"Or use the default custom-recognisers-only mode "
                f"(Scrubber(use_nlp_engine=False)), which needs no model."
            ) from exc

        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
        register_security_recognizers(analyzer)
        return analyzer

    # -- public API ----------------------------------------------------------

    def scrub(self, text: str) -> ScrubResult:
        """Detect entities in ``text`` and return a :class:`ScrubResult`."""
        results = self._detect(text)
        return pseudonymize(text, results)

    def restore(self, scrubbed_text: str, mapping: dict) -> str:
        """Reconstruct the original text from scrubbed text + mapping."""
        return restore(scrubbed_text, mapping)

    def entities(self) -> List[str]:
        """The entity types the security pack can produce."""
        return supported_entities()

    # -- detection -----------------------------------------------------------

    def _detect(self, text: str):
        if self.use_nlp_engine:
            return self._analyzer.analyze(
                text=text,
                language=self.language,
                score_threshold=self.score_threshold,
            )

        # Custom-only: run each recogniser directly (no nlp_artifacts). Presidio's
        # NLP-based ContextAwareEnhancer can't run without spaCy, so we apply a
        # spaCy-free context boost per recogniser (see context_enhancer.py), this
        # restores the intent of the deliberately-low base scores (AWS_SECRET_KEY,
        # HOSTNAME, AWS_ACCOUNT_ID) which otherwise can never cross the threshold here.
        # Then apply the score threshold ourselves.
        results = []
        for rec in self._recognizers:
            rec_results = rec.analyze(
                text,
                entities=rec.supported_entities,
                nlp_artifacts=None,
            )
            enhance_with_context(text, rec_results, getattr(rec, "context", None))
            results.extend(rec_results)
        if self.score_threshold > 0:
            results = [r for r in results if r.score >= self.score_threshold]
        return results


__all__ = ["Scrubber", "DEFAULT_MODEL"]
