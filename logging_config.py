import json
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import g, has_request_context, request, session


class _MinimumLevelFilter(logging.Filter):
    def __init__(self, minimum_level):
        super().__init__()
        self.minimum_level = minimum_level

    def filter(self, record):
        return record.levelno >= self.minimum_level


class _MaximumLevelFilter(logging.Filter):
    def __init__(self, maximum_level):
        super().__init__()
        self.maximum_level = maximum_level

    def filter(self, record):
        return record.levelno < self.maximum_level


class _ExcludeWerkzeugAccessFilter(logging.Filter):
    def filter(self, record):
        return not (record.name == "werkzeug" and " HTTP/" in record.getMessage())


def _file_handler(path, level=logging.DEBUG, formatter=None, filter_=None):
    handler = RotatingFileHandler(
        path,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(formatter or logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    if filter_ is not None:
        handler.addFilter(filter_)
    return handler


def _clear_handlers(logger):
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def configure_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            root_logger.removeHandler(handler)
            handler.close()
    server_handler = _file_handler(
        os.path.join(log_dir, "server.log"),
        filter_=_MaximumLevelFilter(logging.ERROR),
    )
    server_handler.addFilter(_ExcludeWerkzeugAccessFilter())
    root_logger.addHandler(server_handler)
    root_logger.addHandler(_file_handler(
        os.path.join(log_dir, "error.log"),
        level=logging.ERROR,
        filter_=_MinimumLevelFilter(logging.ERROR),
    ))

    access_logger = logging.getLogger("access")
    _clear_handlers(access_logger)
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    access_logger.addHandler(_file_handler(
        os.path.join(log_dir, "access.log"),
        level=logging.INFO,
        formatter=logging.Formatter("%(asctime)s %(message)s"),
    ))

    audit_logger = logging.getLogger("data_changes")
    _clear_handlers(audit_logger)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_logger.addHandler(_file_handler(
        os.path.join(log_dir, "data_changes.log"),
        level=logging.INFO,
        formatter=logging.Formatter("%(asctime)s %(message)s"),
    ))

    werkzeug_logger = logging.getLogger("werkzeug")
    _clear_handlers(werkzeug_logger)
    werkzeug_logger.setLevel(logging.INFO)
    werkzeug_logger.propagate = True

    return access_logger, audit_logger


def current_actor():
    if not has_request_context():
        return {"user_id": "system", "role": "system"}

    actor = getattr(g, "log_actor", None)
    if actor is not None:
        return dict(actor)

    return {
        "user_id": session.get("user", "anonymous"),
        "full_name": session.get("full_name"),
        "role": session.get("role", "anonymous"),
        "shop_id": session.get("selected_shop_id"),
        "request_id": getattr(g, "request_id", None),
    }


def log_access(response, duration_ms):
    actor = current_actor()
    event = {
        "request_id": actor.get("request_id"),
        "user_id": actor.get("user_id"),
        "role": actor.get("role"),
        "shop_id": actor.get("shop_id"),
        "method": request.method,
        "path": request.url_rule.rule if request.url_rule else "<unmatched>",
        "endpoint": request.endpoint,
        "status": response.status_code,
        "duration_ms": round(duration_ms, 2),
        "remote_addr": request.remote_addr,
        "user_agent": request.user_agent.string[:300],
    }
    logging.getLogger("access").info(json.dumps(event, default=str, separators=(",", ":")))
