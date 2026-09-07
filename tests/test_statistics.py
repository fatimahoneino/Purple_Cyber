"""Statistical machinery tests.

The bootstrap is the component whose bugs would be least visible: a subtly wrong
interval still looks like a plausible interval. These tests check it against cases
with known answers.
"""

from __future__ import annotations

import pytest

from purpleforge.scoring.statistics import (
    bootstrap_ci,
    compare,
    distribution,
    percentile,
    run_stability_analysis,
)


class TestPercentile:
    def test_median_of_odd_count(self):
        assert percentile([1, 2, 3], 0.5) == 2

    def test_median_of_even_count_interpolates(self):
        assert percentile([1, 2, 3, 4], 0.5) == 2.5

    def test_bounds(self):
        values = [5, 1, 3, 2, 4]
        assert percentile(values, 0.0) == 1
        assert percentile(values, 1.0) == 5

    def test_single_value(self):
        assert percentile([7], 0.5) == 7

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty sequence"):
            percentile([], 0.5)


class TestBootstrapCI:
    def test_interval_contains_the_mean(self):
        samples = [0.4, 0.45, 0.5, 0.55, 0.6]
        low, high = bootstrap_ci(samples)
        assert low <= sum(samples) / len(samples) <= high

    def test_zero_variance_gives_a_point_interval(self):
        low, high = bootstrap_ci([0.5] * 10)
        assert low == high == 0.5

    def test_interval_respects_metric_bounds(self):
        """Metrics are bounded to [0,1].

        A normal approximation would place the upper bound above 1.0 for samples
        near the ceiling. The percentile bootstrap cannot, because it only ever
        reports means of observed values.
        """
        low, high = bootstrap_ci([0.98, 0.99, 1.0, 1.0, 1.0])
        assert 0.0 <= low <= high <= 1.0

    def test_wider_spread_gives_wider_interval(self):
        tight = bootstrap_ci([0.50, 0.51, 0.49, 0.50, 0.51])
        wide = bootstrap_ci([0.10, 0.90, 0.30, 0.70, 0.50])
        assert (wide[1] - wide[0]) > (tight[1] - tight[0])

    def test_higher_confidence_gives_wider_interval(self):
        samples = [0.3, 0.5, 0.4, 0.6, 0.45, 0.55]
        narrow = bootstrap_ci(samples, confidence=0.80)
        broad = bootstrap_ci(samples, confidence=0.99)
        assert (broad[1] - broad[0]) >= (narrow[1] - narrow[0])

    def test_is_reproducible(self):
        """An interval that moves on every call cannot be cited."""
        samples = [0.2, 0.4, 0.6, 0.8]
        assert bootstrap_ci(samples) == bootstrap_ci(samples)

    def test_single_sample_is_a_point(self):
        assert bootstrap_ci([0.42]) == (0.42, 0.42)

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty sample"):
            bootstrap_ci([])

    def test_invalid_confidence_raises(self):
        with pytest.raises(ValueError, match="strictly between 0 and 1"):
            bootstrap_ci([0.1, 0.2], confidence=1.0)


class TestDistribution:
    def test_summary_statistics(self):
        dist = distribution("precision", [0.4, 0.5, 0.6])
        assert dist.mean == pytest.approx(0.5)
        assert dist.median == 0.5
        assert dist.spread == pytest.approx(0.2)

    def test_stability_classification(self):
        assert distribution("m", [0.50, 0.501, 0.499]).stability == "stable"
        assert distribution("m", [0.1, 0.9, 0.5, 0.3]).stability == "volatile"

    def test_single_sample_has_no_stdev(self):
        assert distribution("m", [0.5]).stdev == 0.0

    def test_zero_mean_does_not_divide_by_zero(self):
        assert distribution("m", [0.0, 0.0]).coefficient_of_variation == 0.0


class TestCompare:
    def test_clear_improvement_is_significant(self):
        baseline = [0.30, 0.31, 0.29, 0.30, 0.31, 0.30]
        candidate = [0.70, 0.71, 0.69, 0.70, 0.71, 0.70]
        result = compare(baseline, candidate)
        assert result["significant"]
        assert result["difference"] > 0
        assert "improvement" in result["interpretation"]

    def test_noise_is_not_reported_as_improvement(self):
        """The guard against celebrating a rule change that did nothing."""
        baseline = [0.40, 0.55, 0.35, 0.60, 0.45, 0.50]
        candidate = [0.42, 0.53, 0.38, 0.58, 0.47, 0.48]
        result = compare(baseline, candidate)
        assert not result["significant"]
        assert "within seed variance" in result["interpretation"]

    def test_regression_is_detected(self):
        result = compare([0.8] * 6, [0.2] * 6)
        assert result["significant"]
        assert result["difference"] < 0
        assert "regression" in result["interpretation"]

    def test_empty_input_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            compare([], [0.5])


class TestStabilityAnalysis:
    def _fake_run(self, recall_by_seed: dict[int, float]):
        def run_once(seed: int) -> dict:
            recall = recall_by_seed[seed]
            return {
                "technique_recall": recall,
                "precision": 0.5,
                "f1_score": 0.5,
                "grade": "C" if recall > 0.5 else "F",
                "detected_techniques": {"T1001"} if recall > 0.5 else set(),
                "all_techniques": {"T1001", "T1002"},
            }

        return run_once

    def test_identifies_flaky_techniques(self):
        """The headline finding: intermittent detection is not coverage."""
        report = run_stability_analysis(
            self._fake_run({1: 0.9, 2: 0.1, 3: 0.9, 4: 0.1}), seeds=[1, 2, 3, 4]
        )
        assert report.technique_detection_rates["T1001"] == 0.5
        assert "T1001" in report.flaky_techniques

    def test_never_detected_is_separate_from_flaky(self):
        report = run_stability_analysis(
            self._fake_run({1: 0.9, 2: 0.9}), seeds=[1, 2]
        )
        assert report.never_detected == ["T1002"]
        assert not report.flaky_techniques

    def test_reliable_techniques_are_always_detected(self):
        report = run_stability_analysis(self._fake_run({1: 0.9, 2: 0.9}), seeds=[1, 2])
        assert report.reliable_techniques == ["T1001"]

    def test_grade_distribution_is_reported(self):
        report = run_stability_analysis(
            self._fake_run({1: 0.9, 2: 0.1, 3: 0.9}), seeds=[1, 2, 3]
        )
        assert report.to_dict()["grade_distribution"] == {"C": 2, "F": 1}
        assert report.modal_grade == "C"

    def test_no_seeds_raises(self):
        with pytest.raises(ValueError, match="at least one seed"):
            run_stability_analysis(self._fake_run({}), seeds=[])
