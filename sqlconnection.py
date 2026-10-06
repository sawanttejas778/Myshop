import logging
import mysql.connector
from dotenv import load_dotenv
import os
import json
import re
import uuid

from logging_config import current_actor

load_dotenv()

_DML_START = re.compile(r"^\s*(?:/\*.*?\*/\s*)*(INSERT|UPDATE|DELETE|REPLACE)\b", re.I | re.S)
_INSERT_COLUMNS = re.compile(
    r"\bINSERT\s+(?:IGNORE\s+)?INTO\s+[\w.`\"]+\s*\((.*?)\)\s*VALUES\b",
    re.I | re.S,
)
_SENSITIVE_FIELD = re.compile(
    r"password|passwd|token|otp|secret|api[_-]?key|bank[_-]?(?:account|ifsc)|account[_-]?number",
    re.I,
)


def _json_value(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return "<binary data>"
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>" if _SENSITIVE_FIELD.search(str(key))
                else _json_value(item)
            )
            for key, item in value.items()
        }
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _parameter_fields(statement, parameters):
    """Associate common INSERT/UPDATE placeholders with their column names."""
    if parameters is None:
        return {}
    if isinstance(parameters, dict):
        return {
            str(key): ("<redacted>" if _SENSITIVE_FIELD.search(str(key)) else _json_value(value))
            for key, value in parameters.items()
        }

    values = list(parameters) if isinstance(parameters, (list, tuple)) else [parameters]
    fields = {}
    insert_match = _INSERT_COLUMNS.search(statement)
    if insert_match:
        columns = [column.strip().strip("`\"") for column in insert_match.group(1).split(",")]
        for index, (column, value) in enumerate(zip(columns, values)):
            fields[column] = "<redacted>" if _SENSITIVE_FIELD.search(column) else _json_value(value)
        for index, value in enumerate(values[len(columns):], start=len(columns)):
            fields[f"parameter_{index + 1}"] = _json_value(value)
        return fields

    update_match = re.search(r"\bSET\b(.*?)(?:\bWHERE\b|$)", statement, re.I | re.S)
    if update_match:
        for assignment in re.finditer(
            r"(?:`([^`]+)`|([\w]+))\s*=\s*(.*?)(?=,\s*(?:`[^`]+`|[\w]+)\s*=|$)",
            update_match.group(1),
            re.S,
        ):
            column = assignment.group(1) or assignment.group(2)
            expression = assignment.group(3).strip()
            first_index = (
                statement[:update_match.start(1) + assignment.start(3)].count("%s")
            )
            placeholder_count = expression.count("%s")
            if placeholder_count:
                assigned_value = values[first_index:first_index + placeholder_count]
                if len(assigned_value) == 1:
                    assigned_value = assigned_value[0]
            else:
                assigned_value = expression
            fields[column] = (
                "<redacted>" if _SENSITIVE_FIELD.search(column)
                else _json_value(assigned_value)
            )

    where_match = re.search(r"\bWHERE\b(.*?)(?:\bORDER\s+BY\b|\bLIMIT\b|$)", statement, re.I | re.S)
    if where_match:
        for condition in re.finditer(
            r"(?:`([^`]+)`|([\w]+))\s*(?:=|<>|!=|>=|<=|>|<|LIKE)\s*%s",
            where_match.group(1),
            re.I,
        ):
            index = statement[:where_match.start(1) + condition.end()].count("%s") - 1
            if 0 <= index < len(values):
                column = condition.group(1) or condition.group(2)
                label = f"where_{column}"
                fields[label] = (
                    "<redacted>" if _SENSITIVE_FIELD.search(column)
                    else _json_value(values[index])
                )

    if not fields:
        for index, value in enumerate(values):
            fields[f"parameter_{index + 1}"] = _json_value(value)
    return fields


def _audit_statement(connection, statement, parameters, rowcount, lastrowid):
    match = _DML_START.match(statement or "")
    if not match:
        return

    operation = match.group(1).upper()
    table_match = re.search(
        r"\b(?:INSERT\s+(?:IGNORE\s+)?INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)\s+([`\w.]+)",
        statement,
        re.I,
    )
    connection.pending_audit.append({
        "transaction_id": connection.transaction_id,
        "request_id": current_actor().get("request_id"),
        "actor": current_actor(),
        "operation": operation,
        "table": table_match.group(1).replace("`", "") if table_match else None,
        "statement": " ".join(statement.split()),
        "changed_fields": _parameter_fields(statement, parameters),
        "affected_rows": rowcount,
        "last_insert_id": lastrowid,
    })


class _AuditedCursor:
    def __init__(self, cursor, connection):
        self._cursor = cursor
        self._connection = connection

    def execute(self, operation, params=None, *args, **kwargs):
        result = self._cursor.execute(operation, params, *args, **kwargs)
        _audit_statement(
            self._connection,
            operation,
            params,
            self._cursor.rowcount,
            self._cursor.lastrowid,
        )
        return result

    def executemany(self, operation, seq_params, *args, **kwargs):
        params_list = list(seq_params)
        result = self._cursor.executemany(operation, params_list, *args, **kwargs)
        for params in params_list:
            _audit_statement(
                self._connection,
                operation,
                params,
                1,
                None,
            )
        return result

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def __enter__(self):
        self._cursor.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._cursor.__exit__(exc_type, exc_value, traceback)

    def __iter__(self):
        return iter(self._cursor)

    def __next__(self):
        return next(self._cursor)


class _AuditedConnection:
    def __init__(self, connection):
        self._connection = connection
        self.pending_audit = []
        self.transaction_id = uuid.uuid4().hex

    def cursor(self, *args, **kwargs):
        return _AuditedCursor(self._connection.cursor(*args, **kwargs), self)

    def commit(self):
        result = self._connection.commit()
        audit_logger = logging.getLogger("data_changes")
        for event in self.pending_audit:
            audit_logger.info(json.dumps(event, default=str, separators=(",", ":")))
        self.pending_audit.clear()
        self.transaction_id = uuid.uuid4().hex
        return result

    def rollback(self):
        result = self._connection.rollback()
        self.pending_audit.clear()
        self.transaction_id = uuid.uuid4().hex
        return result

    def __getattr__(self, name):
        return getattr(self._connection, name)


def get_db():
    """Establish and return an audited MySQL connection and dictionary cursor."""
    conn = mysql.connector.connect(
        host=os.getenv("host"),
        user=os.getenv("user"),
        password=os.getenv("password"),
        database=os.getenv("database")
    )
    audited_conn = _AuditedConnection(conn)
    cursor = audited_conn.cursor(dictionary=True)
    return audited_conn, cursor