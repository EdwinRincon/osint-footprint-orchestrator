import stat

from osint_tool.models import Report
from osint_tool.reporters import write_reports
from osint_tool.sessions import InvestigationSession
from osint_tool.validation import build_target


def test_session_and_nested_reports_use_private_permissions(tmp_path) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    report = Report(target=build_target(username="report"))
    report_directory, report_paths = write_reports(
        report,
        session.directory / "reports" / "entry-1",
        "all",
    )
    session.complete_entry("entry-1", report, report_directory)
    session_json = session.directory / "session.json"
    session_directories = [
        session.directory.parent,
        session.directory,
        *(path for path in session.directory.rglob("*") if path.is_dir()),
    ]

    assert all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in session_directories)
    assert stat.S_IMODE(session_json.stat().st_mode) == 0o600
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in report_paths)
