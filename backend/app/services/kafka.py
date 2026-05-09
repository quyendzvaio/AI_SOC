import logging
from typing import Any

import orjson
from aiokafka import AIOKafkaProducer

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_producer: AIOKafkaProducer | None = None


async def start_kafka() -> None:
    global _producer
    settings = get_settings()
    if _producer or not settings.kafka_bootstrap_servers:
        return
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=orjson.dumps,
    )
    try:
        await producer.start()
    except Exception:
        logger.exception("Kafka producer not ready; API will retry lazily on publish")
        return
    _producer = producer
    logger.info("Kafka producer started")


async def stop_kafka() -> None:
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None


async def publish_security_event(payload: dict[str, Any]) -> None:
    if not _producer:
        await start_kafka()
    if not _producer:
        return
    settings = get_settings()
    try:
        await _producer.send_and_wait(settings.kafka_security_events_topic, payload)
    except Exception:
        logger.exception("Failed to publish security event to Kafka")
