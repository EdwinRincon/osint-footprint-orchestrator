import json
import stat

import pytest

import osint_tool.modules  # noqa: F401
from osint_tool.models import Finding, ModuleResult, Report, Status
from osint_tool.registry import all_modules
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import create_report_dir
from osint_tool.reporters.json_reporter import JsonReporter
from osint_tool.sessions import (
    EDGE_LABEL,
    EntryStatus,
    InvestigationSession,
    SessionError,
    delete_saved_session,
    list_saved_sessions,
    network_recipients,
    safe_report,
)
from osint_tool.validation import build_target


def _session(tmp_path, *, max_depth=2, max_targets=10, api_key=None):
    return InvestigationSession.create(
        tmp_path,
        build_target(username="root"),
        max_depth=max_depth,
        max_targets=max_targets,
        api_key=api_key,
    )


def _finding_report(value: str, entity_type: str = "username") -> Report:
    return Report(
        target=build_target(username="root"),
        results=[
            ModuleResult(
                "profiles",
                Status.OK,
                [
                    Finding(
                        entity_type=entity_type,
                        type="observed",
                        value=value,
                        source="Example source",
                        source_url="https://profiles.example.test/root",
                        detail="Observed value",
                        confidence=0.75,
                    )
                ],
            )
        ],
    )


def test_pivot_options_keep_ambiguous_types_explicit_and_reject_invalid_values(tmp_path) -> None:
    session = _session(tmp_path)
    session.complete_entry("entry-1", _finding_report("alice"))

    choices = session.pivot_choices()
    assert {choice.target_type for choice in choices} == {"username", "name"}
    assert all(choice.target.provided() == frozenset({choice.target_type}) for choice in choices)

    invalid = _session(tmp_path / "invalid")
    invalid.complete_entry("entry-1", _finding_report("hello there!", "email"))
    assert invalid.pivot_choices() == []


def test_finding_value_can_be_explicitly_typed_without_semantic_guessing(tmp_path) -> None:
    session = _session(tmp_path)
    session.complete_entry("entry-1", _finding_report("alice", "public_profile"))

    assert {choice.target_type for choice in session.pivot_choices()} == {"username", "name"}


def test_limits_enforce_depth_and_total_target_maximum(tmp_path) -> None:
    session = _session(tmp_path, max_depth=1, max_targets=2)
    session.complete_entry("entry-1", _finding_report("alice"))
    choice = next(choice for choice in session.pivot_choices() if choice.target_type == "username")
    child = session.add_pivot(choice)
    session.complete_entry(child.entry_id, _finding_report("bob"))

    assert child.depth == 1
    assert session.remaining_depth == 0
    assert session.remaining_targets == 0
    assert not session.can_pivot_from(child.entry_id)
    assert session.pivot_choices() == []


def test_session_limits_cannot_be_raised_above_hard_caps(tmp_path) -> None:
    with pytest.raises(SessionError):
        _session(tmp_path, max_depth=3)
    with pytest.raises(SessionError):
        _session(tmp_path, max_targets=11)


@pytest.mark.parametrize(
    ("root_target", "finding_value", "target_type"),
    [
        ({"username": "Alice"}, " alice ", "username"),
        ({"phone": "+14155552671"}, "+1 (415) 555-2671", "phone"),
    ],
)
def test_deduplicates_case_whitespace_and_phone_formats(
    tmp_path, root_target, finding_value: str, target_type: str
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(**root_target))
    finding = Finding(
        entity_type=target_type,
        type="observed",
        value=finding_value,
        source="Example source",
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(**root_target),
            results=[ModuleResult("profiles", Status.OK, [finding])],
        ),
    )

    assert all(choice.target_type != target_type for choice in session.pivot_choices())


def test_failed_entry_is_persisted_without_losing_session_or_parent(tmp_path) -> None:
    session = _session(tmp_path)
    session.complete_entry("entry-1", _finding_report("alice"))
    choice = next(choice for choice in session.pivot_choices() if choice.target_type == "username")
    child = session.add_pivot(choice)
    session.fail_entry(child.entry_id, "ValueError")

    stored = json.loads((session.directory / "session.json").read_text(encoding="utf-8"))
    assert session.entry(child.entry_id).status is EntryStatus.FAILED
    assert stored["nodes"][1]["status"] == "failed"
    assert session.can_pivot_from("entry-1")


def test_edge_contains_provenance_and_is_labeled_as_hypothesis(tmp_path) -> None:
    session = _session(tmp_path)
    session.complete_entry("entry-1", _finding_report("alice"))
    choice = next(choice for choice in session.pivot_choices() if choice.target_type == "username")
    session.add_pivot(choice)

    edge = session.edges[0]
    assert edge.parent_entry_id == "entry-1"
    assert edge.source_module == "profiles"
    assert edge.source_url == "https://profiles.example.test/root"
    assert edge.evidence_text == "alice — Observed value"
    assert edge.confidence == 0.75
    assert edge.label == EDGE_LABEL


def test_session_output_redacts_api_keys_and_request_urls(tmp_path) -> None:
    configured_value = "hibp-secret-value"
    session = _session(tmp_path, api_key=configured_value)
    report = Report(
        target=build_target(username="root"),
        results=[
            ModuleResult(
                "profiles",
                Status.OK,
                [
                    Finding(
                        entity_type="username",
                        type="observed",
                        value="alice",
                        source="Source",
                        source_url=(
                            "https://api.example.test/request/alice?api_key=" + configured_value
                        ),
                        detail=(
                            "Request https://api.example.test/request?key=" + configured_value
                        ),
                        raw={
                            "api_key": configured_value,
                            "request_url": "https://api.example.test/request",
                        },
                    )
                ],
            )
        ],
    )
    report_directory, _ = write_reports(
        safe_report(report, configured_value),
        session.directory / "reports" / "entry-1",
        "all",
    )
    session.complete_entry("entry-1", report, report_directory)
    choice = next(choice for choice in session.pivot_choices() if choice.target_type == "username")
    session.add_pivot(choice)

    outputs = [
        path.read_text(encoding="utf-8")
        for path in session.directory.rglob("*")
        if path.is_file()
    ]
    output = "\n".join(outputs)
    assert configured_value not in output
    assert "api.example.test" not in output
    assert "request?" not in output
    assert "hibp_api_key" not in output
    assert '"api_key":' not in output


def test_delete_removes_only_the_session_directory(tmp_path) -> None:
    session = _session(tmp_path)
    directory = session.directory
    sessions_root = directory.parent

    session.delete()

    assert not directory.exists()
    assert sessions_root.is_dir()


def test_saved_session_can_be_found_and_deleted_without_in_memory_state(tmp_path) -> None:
    session = _session(tmp_path)
    session_id = session.session_id

    saved = list_saved_sessions(tmp_path)
    assert len(saved) == 1
    assert saved[0].session_id == session_id
    assert saved[0].status == "running"
    assert saved[0].safe_to_delete

    delete_saved_session(tmp_path, session_id)
    assert not session.directory.exists()


def test_session_uses_the_same_default_permissions_as_report_files(tmp_path) -> None:
    session = _session(tmp_path)
    report = Report(target=build_target(username="report"))
    report_directory = create_report_dir(tmp_path, report)
    report_json = JsonReporter().write(report, report_directory)[0]
    session_json = session.directory / "session.json"

    assert stat.S_IMODE(session.directory.stat().st_mode) == stat.S_IMODE(
        report_directory.stat().st_mode
    )
    assert stat.S_IMODE(session_json.stat().st_mode) == stat.S_IMODE(report_json.stat().st_mode)


def test_every_network_module_discloses_its_recipients() -> None:
    network_modules = [
        module_type()
        for module_type in all_modules().values()
        if getattr(module_type, "requires_network", False)
    ]

    assert network_modules
    for module in network_modules:
        assert network_recipients(module)


def test_network_modules_without_recipient_metadata_fail_closed() -> None:
    class UndisclosedModule:
        requires_network = True

    with pytest.raises(SessionError, match="destinatarios"):
        network_recipients(UndisclosedModule())
