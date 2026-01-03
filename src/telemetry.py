"""OpenTelemetry configuration for logs, traces, and metrics."""

import logging
from typing import Optional
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import get_aggregated_resources, OTELResourceDetector
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler

from .config import Config


def setup_telemetry(cfg: Config) -> tuple[Optional[TracerProvider], Optional[MeterProvider], Optional[LoggerProvider]]:
    """Initialize OpenTelemetry with OTLP exporters based on configuration."""

    resource = get_aggregated_resources(detectors=[OTELResourceDetector()])

    trace_provider = None
    meter_provider = None
    logger_provider = None

    # Traces
    if cfg.otlp_traces_enabled:
        trace_provider = TracerProvider(resource=resource)
        otlp_trace_exporter = OTLPSpanExporter()
        trace_provider.add_span_processor(BatchSpanProcessor(otlp_trace_exporter))
        trace.set_tracer_provider(trace_provider)
        logging.info("OTLP traces enabled")
    else:
        logging.info("OTLP traces disabled")

    # Metrics
    if cfg.otlp_metrics_enabled:
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(),
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        logging.info("OTLP metrics enabled")
    else:
        logging.info("OTLP metrics disabled")

    # Logs
    if cfg.otlp_logs_enabled:
        logger_provider = LoggerProvider()
        set_logger_provider(logger_provider)
        log_exporter = OTLPLogExporter()
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
        logging.getLogger().addHandler(handler)
        logging.info("OTLP logs enabled")
    else:
        logging.info("OTLP logs disabled")

    return trace_provider, meter_provider, logger_provider

def create_metrics(meter_provider: Optional[MeterProvider]):
    """Create application metrics.

    Args:
        meter_provider: MeterProvider instance, or None if metrics disabled

    Returns:
        Dictionary of metrics, or None if meter_provider is None
    """
    if not meter_provider:
        return None

    meter = meter_provider.get_meter(__name__)
    return {
        "scan_total": meter.create_gauge(
            "image_scan",
            description="Current vulnerability count per image by severity",
            unit="1",
        ),
    }
