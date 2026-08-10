from __future__ import annotations

from importlib.metadata import version


def test_runtime_dependency_versions_are_the_proven_set() -> None:
    expected = {
        "boto3": "1.43.51",
        "botocore": "1.43.51",
        "clickhouse-connect": "1.5.0",
        "eval-type-backport": "0.4.0",
        "opentelemetry-exporter-otlp-proto-http": "1.44.0",
        "opentelemetry-instrumentation-fastapi": "0.65b0",
        "opentelemetry-sdk": "1.44.0",
        "redis": "8.0.1",
        "requests": "2.34.2",
    }

    assert {name: version(name) for name in expected} == expected


def test_updated_client_surfaces_used_by_tokendna_are_importable() -> None:
    import boto3
    import clickhouse_connect
    import redis
    import requests
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    assert boto3.Session(region_name="us-east-1").region_name == "us-east-1"
    assert isinstance(redis.ConnectionPool(host="localhost", port=6379), redis.ConnectionPool)
    assert callable(clickhouse_connect.get_client)
    assert isinstance(requests.Session(), requests.Session)
    assert callable(OTLPSpanExporter)
    assert callable(FastAPIInstrumentor().instrument_app)
