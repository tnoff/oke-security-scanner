"""Tests for telemetry module."""

import pytest
from unittest.mock import Mock, patch
from src.telemetry import setup_telemetry, create_metrics, Metrics


class TestTelemetry:
    """Tests for telemetry module."""

    @patch('src.telemetry.get_aggregated_resources')
    @patch('src.telemetry.MeterProvider')
    @patch('src.telemetry.LoggerProvider')
    @patch('src.telemetry.PeriodicExportingMetricReader')
    @patch('src.telemetry.OTLPMetricExporter')
    @patch('src.telemetry.OTLPLogExporter')
    @patch('src.telemetry.BatchLogRecordProcessor')
    @patch('src.telemetry.metrics')
    def test_setup_telemetry_returns_meter_logger(
        self,
        mock_metrics_module,
        mock_batch_log_processor,
        mock_log_exporter,
        mock_metric_exporter,
        mock_metric_reader,
        mock_logger_provider_class,
        mock_meter_provider_class,
        mock_get_resources,
        base_config,
    ):
        """Test that setup_telemetry returns meter_provider and logger_provider."""
        # Setup mocks
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()

        mock_meter_provider_class.return_value = mock_meter_provider
        mock_logger_provider_class.return_value = mock_logger_provider

        # Enable OTLP features
        base_config.otlp_metrics_enabled = True
        base_config.otlp_logs_enabled = True

        meter_provider, logger_provider = setup_telemetry(base_config)

        assert meter_provider == mock_meter_provider
        assert logger_provider == mock_logger_provider

    @patch('src.telemetry.metrics')
    @patch('src.telemetry.MeterProvider')
    @patch('src.telemetry.LoggerProvider')
    @patch('src.telemetry.PeriodicExportingMetricReader')
    @patch('src.telemetry.OTLPMetricExporter')
    @patch('src.telemetry.OTLPLogExporter')
    @patch('src.telemetry.BatchLogRecordProcessor')
    def test_setup_telemetry_sets_global_providers(
        self,
        mock_batch_log_processor,
        mock_log_exporter,
        mock_metric_exporter,
        mock_metric_reader,
        mock_logger_provider_class,
        mock_meter_provider_class,
        mock_metrics,
        base_config,
    ):
        """Test that setup_telemetry sets global meter provider."""
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()

        mock_meter_provider_class.return_value = mock_meter_provider
        mock_logger_provider_class.return_value = mock_logger_provider

        # Enable OTLP features
        base_config.otlp_metrics_enabled = True
        base_config.otlp_logs_enabled = True

        setup_telemetry(base_config)

        # Verify global meter provider is set
        mock_metrics.set_meter_provider.assert_called_once_with(mock_meter_provider)

    def test_create_metrics_returns_metrics_dataclass(self):
        """Test that create_metrics returns a Metrics dataclass."""
        mock_meter_provider = Mock()
        mock_meter = Mock()
        mock_gauge = Mock()

        mock_meter_provider.get_meter.return_value = mock_meter
        mock_meter.create_gauge.return_value = mock_gauge

        result = create_metrics(mock_meter_provider)

        assert isinstance(result, Metrics)
        assert result.scan_total == mock_gauge

    def test_create_metrics_creates_image_scan_gauge(self):
        """Test that create_metrics creates image_scan gauge with correct parameters."""
        mock_meter_provider = Mock()
        mock_meter = Mock()
        mock_gauge = Mock()

        mock_meter_provider.get_meter.return_value = mock_meter
        mock_meter.create_gauge.return_value = mock_gauge

        create_metrics(mock_meter_provider)

        mock_meter.create_gauge.assert_called_once()
        call_args = mock_meter.create_gauge.call_args
        assert call_args[0][0] == "image_scan"

    def test_create_metrics_returns_none_when_meter_provider_none(self):
        """create_metrics returns None when meter_provider is None (metrics disabled)."""
        assert create_metrics(None) is None

    @patch('src.telemetry.get_aggregated_resources')
    def test_setup_telemetry_disabled_returns_none_providers(self, _mock_get_resources, base_config):
        """When both OTLP flags are off, setup_telemetry returns (None, None)."""
        base_config.otlp_metrics_enabled = False
        base_config.otlp_logs_enabled = False

        meter_provider, logger_provider = setup_telemetry(base_config)

        assert meter_provider is None
        assert logger_provider is None
