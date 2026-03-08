"""
Drift Detection Evaluator

- "Automated drift detection: does the agent still behave as designed?"
"""

from dataclasses import dataclass


@dataclass
class DriftResult:
    metric: str
    baseline_value: float
    current_value: float
    drift_detected: bool
    drift_magnitude: float
    details: str


class DriftDetector:
    """Detects behavioral drift in agent outputs over time.

    Compares current behavior against a recorded baseline to catch
    when agents start behaving differently than intended.
    """

    def __init__(self, drift_threshold: float = 0.15):
        self.drift_threshold = drift_threshold
        self.baselines: dict[str, float] = {}

    def set_baseline(self, metric: str, value: float):
        self.baselines[metric] = value

    def set_baselines(self, baselines: dict[str, float]):
        self.baselines.update(baselines)

    def check(self, metric: str, current_value: float) -> DriftResult:
        baseline = self.baselines.get(metric)
        if baseline is None:
            return DriftResult(
                metric=metric,
                baseline_value=0.0,
                current_value=current_value,
                drift_detected=False,
                drift_magnitude=0.0,
                details=f"No baseline set for '{metric}', recording current as baseline",
            )

        if baseline == 0:
            magnitude = abs(current_value)
        else:
            magnitude = abs(current_value - baseline) / abs(baseline)

        drifted = magnitude > self.drift_threshold

        return DriftResult(
            metric=metric,
            baseline_value=baseline,
            current_value=current_value,
            drift_detected=drifted,
            drift_magnitude=magnitude,
            details=(
                f"DRIFT: {metric} changed by {magnitude:.1%} (threshold: {self.drift_threshold:.1%})"
                if drifted
                else f"OK: {metric} within tolerance ({magnitude:.1%} < {self.drift_threshold:.1%})"
            ),
        )

    def check_all(self, current_metrics: dict[str, float]) -> list[DriftResult]:
        return [self.check(metric, value) for metric, value in current_metrics.items()]
