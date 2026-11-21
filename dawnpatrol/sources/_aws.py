"""Shared AWS session handling for the aws_cloudtrail and aws_guardduty sources.

Not a plugin (the leading underscore keeps the registry from loading it).

Credentials, in order of preference:

* nothing set: boto3's default chain (instance profile, ECS task role,
  ``AWS_PROFILE``, ``AWS_ACCESS_KEY_ID``...). Use this when DawnPatrol runs
  inside AWS or with a mounted ``~/.aws``.
* ``DAWNPATROL_SOURCE_AWS_ACCESS_KEY_ID`` + ``..._SECRET_ACCESS_KEY``: a
  dedicated read-only IAM user (see docs/aws-setup.md).
* ``DAWNPATROL_SOURCE_AWS_ROLE_ARN`` (optional, with ``..._EXTERNAL_ID``):
  assume a read-only role on top of either of the above, e.g. a role in the
  account being monitored.

boto3 is an optional dependency (``pip install "dawnpatrol[aws]"``); without
it both sources report a clear error instead of failing to import.
"""

from __future__ import annotations

from typing import Any

from ..secrets import read_env, read_list, read_secret

ENV = "DAWNPATROL_SOURCE_AWS_"


class AwsUnavailable(RuntimeError):
    """boto3 is missing or credentials could not be established."""


def default_region() -> str:
    return read_env(f"{ENV}REGION", "") or "us-east-1"


def session(region: str | None = None) -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise AwsUnavailable("boto3 is not installed; install dawnpatrol[aws]") from exc

    kwargs: dict[str, Any] = {"region_name": region or default_region()}
    key_id = read_env(f"{ENV}ACCESS_KEY_ID", "")
    secret = read_secret(f"{ENV}SECRET_ACCESS_KEY").get()
    if key_id and secret:
        kwargs.update(aws_access_key_id=key_id, aws_secret_access_key=secret)
    base = boto3.Session(**kwargs)

    role_arn = read_env(f"{ENV}ROLE_ARN", "")
    if not role_arn:
        return base
    assume: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "dawnpatrol",
                              "DurationSeconds": 3600}
    external_id = read_env(f"{ENV}EXTERNAL_ID", "")
    if external_id:
        assume["ExternalId"] = external_id
    creds = base.client("sts").assume_role(**assume)["Credentials"]
    return boto3.Session(
        region_name=kwargs["region_name"],
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def regions(name: str) -> list[str]:
    """A comma-separated region list setting, defaulting to the base region."""
    return read_list(name) or [default_region()]


def error_text(exc: Exception) -> str:
    """A short, credential-free description of a boto3/botocore error."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict) and "Error" in response:
        err = response["Error"]
        return f"{err.get('Code', type(exc).__name__)}: {err.get('Message', '')}"[:300]
    return f"{type(exc).__name__}: {exc}"[:300]
