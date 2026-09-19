"""The read-only SQL tool's safety comes from structure, not from asking nicely."""

from __future__ import annotations

import pytest

from dawnpatrol.agent import sqlguard

RUN = "run123"


def test_plain_select_is_allowed_and_gains_a_limit():
    sql, cap = sqlguard.validate(
        f"SELECT src_ip FROM events WHERE run_id='{RUN}'", RUN)
    assert sql.lower().endswith(f"limit {cap}")


def test_existing_limit_is_respected_and_capped():
    sql, cap = sqlguard.validate(
        f"SELECT src_ip FROM events WHERE run_id='{RUN}' LIMIT 5", RUN)
    assert cap == 5
    sql, cap = sqlguard.validate(
        f"SELECT src_ip FROM events WHERE run_id='{RUN}' LIMIT 99999", RUN)
    assert cap == sqlguard.MAX_LIMIT


def test_cte_is_allowed():
    sql, _ = sqlguard.validate(
        f"WITH top AS (SELECT src_ip, COUNT(*) c FROM events "
        f"WHERE run_id='{RUN}' GROUP BY src_ip) SELECT * FROM top", RUN)
    assert sql.lower().startswith("with")


@pytest.mark.parametrize("sql", [
    "DELETE FROM events",
    "UPDATE events SET src_ip='x'",
    "INSERT INTO events (id) VALUES (1)",
    "DROP TABLE events",
    "TRUNCATE events",
    "ALTER TABLE events ADD COLUMN x INT",
    "CREATE TABLE bad (x INT)",
    "PRAGMA table_info(events)",
    "ATTACH DATABASE '/etc/passwd' AS p",
    "SELECT load_file('/etc/passwd')",
    "SELECT * FROM events INTO OUTFILE '/tmp/x'",
])
def test_writes_and_escapes_are_rejected(sql):
    with pytest.raises(sqlguard.SQLRejected):
        sqlguard.validate(sql, RUN)


def test_stacked_statements_are_rejected():
    with pytest.raises(sqlguard.SQLRejected):
        sqlguard.validate(
            f"SELECT 1 FROM events WHERE run_id='{RUN}'; DROP TABLE events", RUN)


def test_comment_hidden_write_is_rejected():
    with pytest.raises(sqlguard.SQLRejected):
        sqlguard.validate(
            f"SELECT 1 FROM events WHERE run_id='{RUN}' /* x */; DELETE FROM runs", RUN)


def test_tables_outside_the_allowlist_are_rejected():
    for table in ("runs", "deliveries", "enrichment_cache", "suppressions", "sqlite_master"):
        with pytest.raises(sqlguard.SQLRejected, match="not readable"):
            sqlguard.validate(f"SELECT * FROM {table}", RUN)


def test_events_query_must_be_scoped_to_the_run():
    with pytest.raises(sqlguard.SQLRejected, match="run_id"):
        sqlguard.validate("SELECT * FROM events", RUN)


def test_mentioning_run_id_without_scoping_to_it_is_rejected():
    """Merely containing the text "run_id" must not satisfy the check.

    A prior version of this guard did a substring search for "run_id" in the
    query text, which this string would pass while reading every run still in
    the raw retention window, not just RUN.
    """
    with pytest.raises(sqlguard.SQLRejected, match="run_id"):
        sqlguard.validate(
            "SELECT *, 'run_id' AS note FROM events WHERE src_ip='1.2.3.4'", RUN)


def test_scoping_to_a_different_run_id_is_rejected():
    with pytest.raises(sqlguard.SQLRejected, match="run_id"):
        sqlguard.validate("SELECT * FROM events WHERE run_id='someone-elses-run'", RUN)


def test_qualified_and_in_clause_run_id_scoping_is_accepted():
    sql, _ = sqlguard.validate(
        f"SELECT * FROM events e WHERE e.run_id = '{RUN}'", RUN)
    assert "events" in sql
    sql, _ = sqlguard.validate(
        f"SELECT * FROM events WHERE run_id IN ('{RUN}', 'other')", RUN)
    assert "events" in sql


@pytest.mark.parametrize("sql", [
    "SELECT * FROM(events)",
    "SELECT * FROM (events)",
    "SELECT * FROM((events))",
])
def test_parenthesized_events_reference_still_requires_run_scope(sql):
    """A missing space after FROM must not hide the table from the run-id check."""
    with pytest.raises(sqlguard.SQLRejected, match="run_id"):
        sqlguard.validate(sql, RUN)


@pytest.mark.parametrize("table", ("runs", "deliveries", "enrichment_cache",
                                   "suppressions", "sqlite_master"))
def test_parenthesized_disallowed_table_is_still_rejected(table):
    """The same trick must not hide a disallowed table from the allowlist check."""
    with pytest.raises(sqlguard.SQLRejected, match="not readable"):
        sqlguard.validate(f"SELECT * FROM({table})", RUN)


def test_subquery_in_from_is_not_mistaken_for_a_table_reference():
    # Must not be rejected as an illegal reference to a table named "select".
    sql, _ = sqlguard.validate(
        f"SELECT * FROM (SELECT src_ip FROM events WHERE run_id='{RUN}') t", RUN)
    assert "events" in sql


def test_long_term_tables_need_no_run_scope():
    sql, _ = sqlguard.validate("SELECT domain FROM ioc_dns WHERE domain LIKE '%evil%'", RUN)
    assert "ioc_dns" in sql
    sql, _ = sqlguard.validate("SELECT value FROM entities WHERE etype='domain'", RUN)
    assert "entities" in sql


def test_empty_and_oversized_queries_are_rejected():
    with pytest.raises(sqlguard.SQLRejected):
        sqlguard.validate("", RUN)
    with pytest.raises(sqlguard.SQLRejected):
        sqlguard.validate("SELECT " + "x" * 5000, RUN)


def test_schema_description_names_the_run_and_dialect():
    text = sqlguard.describe_schema(RUN, "sqlite")
    assert RUN in text and "sqlite" in text
    assert "ioc_dns" in text and "entities" in text
