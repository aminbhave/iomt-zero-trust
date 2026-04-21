"""Unit tests for the Dynamic Trust Scoring Algorithm (DTSA)."""

import pytest
from cloud.lambda_dtsa.handler import (
    deviation,
    calculate_trust_score,
    decide,
    update_ema,
    update_sigma_ema,
    score_packet,
    DeviceBaseline,
    _local_baselines,
    ALPHA,
    BETA,
    GAMMA,
    EPSILON,
)


class TestDeviation:
    def test_zero_deviation(self):
        assert deviation(5.0, 5.0, 1.0) == pytest.approx(0.0)

    def test_one_sigma(self):
        result = deviation(6.0, 5.0, 1.0)
        assert result == pytest.approx(1.0, abs=1e-4)

    def test_three_sigma(self):
        result = deviation(8.0, 5.0, 1.0)
        assert result == pytest.approx(3.0, abs=1e-4)

    def test_zero_sigma_uses_epsilon(self):
        result = deviation(5.5, 5.0, 0.0)
        expected = 0.5 / EPSILON
        assert result == pytest.approx(expected, rel=1e-3)

    def test_negative_deviation(self):
        result = deviation(2.0, 5.0, 1.0)
        assert result == pytest.approx(3.0, abs=1e-4)


class TestTrustScore:
    def test_perfect_score(self):
        assert calculate_trust_score(0, 0, 0) == 100.0

    def test_weights_sum(self):
        assert ALPHA + BETA + GAMMA == 100

    def test_moderate_deviation(self):
        score = calculate_trust_score(0.5, 0.5, 0.5)
        expected = 100 - (30 * 0.5 + 50 * 0.5 + 20 * 0.5)
        assert score == pytest.approx(expected)

    def test_clamped_to_zero(self):
        score = calculate_trust_score(10, 10, 10)
        assert score == 0.0

    def test_clamped_to_100(self):
        score = calculate_trust_score(-1, -1, -1)
        assert score == 100.0


class TestDecision:
    def test_allow(self):
        assert decide(60) == "ALLOW"
        assert decide(95) == "ALLOW"
        assert decide(100) == "ALLOW"

    def test_step_up_auth(self):
        assert decide(59.9) == "STEP_UP_AUTH"
        assert decide(40) == "STEP_UP_AUTH"
        assert decide(50) == "STEP_UP_AUTH"

    def test_quarantine(self):
        assert decide(39.9) == "QUARANTINE"
        assert decide(0) == "QUARANTINE"
        assert decide(10) == "QUARANTINE"


class TestEMA:
    def test_ema_basic(self):
        result = update_ema(10.0, 20.0)
        assert result == pytest.approx(0.1 * 20 + 0.9 * 10)

    def test_ema_stable(self):
        result = update_ema(5.0, 5.0)
        assert result == pytest.approx(5.0)

    def test_sigma_update(self):
        new_sigma = update_sigma_ema(1.0, 5.0, 3.0)
        assert new_sigma > 0


class TestScorePacket:
    @pytest.fixture(autouse=True)
    def clear_baselines(self):
        _local_baselines.clear()
        yield
        _local_baselines.clear()

    def test_normal_packet_allowed(self):
        _local_baselines["dev1"] = DeviceBaseline(
            device_id="dev1",
            mu_freq=1.0, sigma_freq=0.2,
            mu_size=2000, sigma_size=200,
            mu_geo=0.0, sigma_geo=0.01,
        )
        result = score_packet("dev1", packet_freq=1.0, payload_size=2000)
        assert result["decision"] == "ALLOW"
        assert result["trust_score"] >= 60

    def test_anomalous_payload_quarantined(self):
        bl = DeviceBaseline(
            device_id="dev2",
            mu_freq=1.0, sigma_freq=0.2,
            mu_size=2000, sigma_size=200,
        )
        _local_baselines["dev2"] = bl
        # 3-sigma spike (500%) in payload size
        attack_size = bl.mu_size + 3 * bl.sigma_size * 5
        result = score_packet("dev2", packet_freq=1.0, payload_size=attack_size)
        assert result["decision"] == "QUARANTINE"
        assert result["trust_score"] < 40

    def test_baseline_updates_on_allow(self):
        _local_baselines["dev3"] = DeviceBaseline(
            device_id="dev3",
            mu_freq=1.0, sigma_freq=0.2,
            mu_size=2000, sigma_size=200,
        )
        old_mu = _local_baselines["dev3"].mu_size
        score_packet("dev3", packet_freq=1.0, payload_size=2050)
        new_mu = _local_baselines["dev3"].mu_size
        assert new_mu != old_mu  # EMA updated

    def test_baseline_not_updated_on_quarantine(self):
        bl = DeviceBaseline(
            device_id="dev4",
            mu_freq=1.0, sigma_freq=0.2,
            mu_size=2000, sigma_size=200,
        )
        _local_baselines["dev4"] = bl
        old_count = bl.packet_count
        score_packet("dev4", packet_freq=1.0, payload_size=50000)
        assert _local_baselines["dev4"].packet_count == old_count

    def test_latency_under_threshold(self):
        _local_baselines["dev5"] = DeviceBaseline(device_id="dev5")
        result = score_packet("dev5", packet_freq=1.0, payload_size=2000)
        assert result["detection_latency_ms"] < 50  # well under 180ms target
