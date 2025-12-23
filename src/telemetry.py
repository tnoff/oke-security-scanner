"""OpenTelemetry configuration for logs, traces, and metrics."""

import logging
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import get_aggregated_resources, OTELResourceDetector
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.metrics import get_meter_provider


def setup_telemetry() -> tuple[trace.Tracer, metrics.Meter]:
    """Initialize OpenTelemetry with OTLP exporters."""

    resource = get_aggregated_resources(detectors=[OTELResourceDetector()])

    # Traces
    trace_provider = TracerProvider(resource=resource)
    otlp_trace_exporter = OTLPSpanExporter()
    trace_provider.add_span_processor(BatchSpanProcessor(otlp_trace_exporter))
    trace.set_tracer_provider(trace_provider)

    # Metrics
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(),
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    # Set logging
    logger_provider = LoggerProvider()
    set_logger_provider(logger_provider)
    log_exporter = OTLPLogExporter()
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
    handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
    logging.getLogger().addHandler(handler)

    # providers
    tracer = trace.get_tracer(__name__)
    meter = get_meter_provider().get_meter(__name__, '0.0.1')
    return tracer, meter, logger_provider

def create_metrics(meter: metrics.Meter):
    """Create application metrics."""
    return {
        "scan_total": meter.create_gauge(
            "image_scan",
            description="Current vulnerability count per image by severity",
            unit="1",
        ),
    }
