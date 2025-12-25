"""Tests for telemetry module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.telemetry import setup_telemetry, create_metrics


class TestTelemetry:
    """Tests for telemetry module."""

    @patch('src.telemetry.get_aggregated_resources')
    @patch('src.telemetry.TracerProvider')
    @patch('src.telemetry.MeterProvider')
    @patch('src.telemetry.LoggerProvider')
    @patch('src.telemetry.OTLPSpanExporter')
    @patch('src.telemetry.PeriodicExportingMetricReader')
    @patch('src.telemetry.OTLPMetricExporter')
    @patch('src.telemetry.OTLPLogExporter')
    @patch('src.telemetry.BatchSpanProcessor')
    @patch('src.telemetry.BatchLogRecordProcessor')
    @patch('src.telemetry.trace')
    @patch('src.telemetry.get_meter_provider')
    def test_setup_telemetry_returns_tracer_meter_logger(
        self,
        mock_get_meter_provider,
        mock_trace,
        mock_batch_log_processor,
        mock_batch_span_processor,
        mock_log_exporter,
        mock_metric_exporter,
        mock_metric_reader,
        mock_span_exporter,
        mock_logger_provider_class,
        mock_meter_provider_class,
        mock_tracer_provider_class,
        mock_get_resources,
    ):
        """Test that setup_telemetry returns tracer, meter, and logger_provider."""
        # Setup mocks
        mock_tracer = Mock()
        mock_meter = Mock()
        mock_logger_provider = Mock()
        mock_meter_provider = Mock()

        mock_trace.get_tracer.return_value = mock_tracer
        mock_get_meter_provider.return_value = mock_meter_provider
        mock_meter_provider.get_meter.return_value = mock_meter
        mock_logger_provider_class.return_value = mock_logger_provider

        tracer, meter, logger_provider = setup_telemetry()

        assert tracer == mock_tracer
        assert meter == mock_meter
        assert logger_provider == mock_logger_provider

    @patch('src.telemetry.trace')
    @patch('src.telemetry.metrics')
    @patch('src.telemetry.TracerProvider')
    @patch('src.telemetry.MeterProvider')
    @patch('src.telemetry.LoggerProvider')
    @patch('src.telemetry.OTLPSpanExporter')
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
        mock_span_exporter,
        mock_logger_provider_class,
        mock_meter_provider_class,
        mock_tracer_provider_class,
        mock_metrics,
        mock_trace,
    ):
        """Test that setup_telemetry sets global trace and meter providers."""
        mock_trace_provider = Mock()
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()

        mock_tracer_provider_class.return_value = mock_trace_provider
        mock_meter_provider_class.return_value = mock_meter_provider
        mock_logger_provider_class.return_value = mock_logger_provider

        setup_telemetry()

        # Verify global providers are set
        mock_trace.set_tracer_provider.assert_called_once_with(mock_trace_provider)
        mock_metrics.set_meter_provider.assert_called_once_with(mock_meter_provider)

    def test_create_metrics_returns_dict(self):
        """Test that create_metrics returns a dictionary with metrics."""
        mock_meter = Mock()
        mock_gauge = Mock()

        mock_meter.create_gauge.return_value = mock_gauge

        result = create_metrics(mock_meter)

        assert isinstance(result, dict)
        assert "scan_total" in result
        assert result["scan_total"] == mock_gauge

    def test_create_metrics_creates_scan_total_gauge(self):
        """Test that create_metrics creates scan_total gauge with correct parameters."""
        mock_meter = Mock()

        create_metrics(mock_meter)

        # Verify gauge was created with correct parameters
        mock_meter.create_gauge.assert_called_once()
        call_args = mock_meter.create_gauge.call_args
        assert call_args[0][0] == "image_scan"  # name parameter
        assert "description" in call_args[1]  # Has description

    def test_create_metrics_gauge_has_unit(self):
        """Test that gauge is created with unit."""
        mock_meter = Mock()

        create_metrics(mock_meter)

        call_args = mock_meter.create_gauge.call_args
        assert "unit" in call_args[1]
        assert call_args[1]["unit"] == "1"
