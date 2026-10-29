"""Column-level classification: combine detector signals into one verdict.

For each column, per category:
  confidence = max(pattern confidence over matching values, if any)
  + 0.05 when the dictionary detector agrees (capped at 0.98)
  or the dictionary confidence alone when no value pattern matched.

The winning category is the highest-confidence one; ties break toward the
more sensitive category so classification errs toward protection.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from privacy_platform.detectors import DEFAULT_DETECTORS, DictionaryDetector, PatternDetector
from privacy_platform.models import (
    DEFAULT_ACTION_BY_SENSITIVITY,
    SENSITIVITY_BY_CATEGORY,
    ColumnClassification,
    PIICategory,
    Sensitivity,
)

_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}


class ColumnClassifier:
    def __init__(self, detectors: list | None = None) -> None:
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS

    def classify_column(self, field: str, values: Iterable[object]) -> ColumnClassification:
        vals = ["" if v is None else str(v) for v in values]
        non_empty = [v for v in vals if v.strip()]
        pattern_best: dict[PIICategory, float] = {}
        dict_category: PIICategory | None = None
        used: set[str] = set()
        for detector in self.detectors:
            if isinstance(detector, DictionaryDetector):
                dict_category = detector.category_for_field(field)
                if dict_category is not None:
                    used.add(detector.name)
                continue
            if isinstance(detector, PatternDetector):
                used.add(detector.name)
            for value in non_empty:
                for finding in detector.scan_value(field, value):
                    pattern_best[finding.category] = max(
                        pattern_best.get(finding.category, 0.0), finding.confidence
                    )
        best_category = PIICategory.UNKNOWN
        best_conf = 0.0
        best_rate = 0.0
        for category, conf in pattern_best.items():
            rate = self._match_rate(field, non_empty, category)
            if dict_category == category:
                conf = min(0.98, conf + 0.05)
            if (conf, _SENSITIVITY_RANK[SENSITIVITY_BY_CATEGORY[category]]) > (
                best_conf,
                _SENSITIVITY_RANK[SENSITIVITY_BY_CATEGORY[best_category]],
            ):
                best_category, best_conf, best_rate = category, conf, rate
        if best_category is PIICategory.UNKNOWN and dict_category is not None:
            best_category, best_conf = dict_category, 0.70
            best_rate = 1.0 if non_empty else 0.0
            used.add("dictionary")
        if best_category is PIICategory.UNKNOWN:
            return ColumnClassification(
                field=field,
                category=PIICategory.UNKNOWN,
                confidence=0.0,
                sensitivity=Sensitivity.PUBLIC,
                suggested_action=DEFAULT_ACTION_BY_SENSITIVITY[Sensitivity.PUBLIC],
                match_rate=0.0,
                detectors=sorted(used),
            )
        sensitivity = SENSITIVITY_BY_CATEGORY[best_category]
        return ColumnClassification(
            field=field,
            category=best_category,
            confidence=round(best_conf, 3),
            sensitivity=sensitivity,
            suggested_action=DEFAULT_ACTION_BY_SENSITIVITY[sensitivity],
            match_rate=round(best_rate, 3),
            detectors=sorted(used),
        )

    def _match_rate(self, field: str, values: list[str], category: PIICategory) -> float:
        if not values:
            return 0.0
        pattern = next(
            (d for d in self.detectors if isinstance(d, PatternDetector)), None
        )
        if pattern is None:
            return 0.0
        hits = sum(
            1
            for v in values
            if any(f.category == category for f in pattern.scan_value(field, v))
        )
        return hits / len(values)

    def classify_dataset(
        self, records: list[Mapping[str, object]]
    ) -> list[ColumnClassification]:
        if not records:
            return []
        fields: list[str] = []
        for record in records:
            for key in record:
                if key not in fields:
                    fields.append(key)
        return [
            self.classify_column(field, [r.get(field) for r in records])
            for field in fields
        ]
