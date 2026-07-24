# report_invariants.py
# Internal-consistency checks for a built RunReport (Phase 3, post-live-test debugging track).
"""Report invariants (Phase 3, post-live-test debugging track).

``check_report_invariants(report)`` is a pure function returning a list of
human-readable violation strings (empty means the report is internally
consistent). It is called once, automatically, inside
``apex_host.eval.report.build_report()`` — the violations are recorded on
``RunReport.invariant_violations`` and surfaced in both ``format_text()``
and ``to_json_dict()``. ``build_report()`` itself NEVER raises because of
a violation: "In production, prefer a safe diagnostic status rather than
crashing after an engagement, while recording invariant violations." A
non-empty ``invariant_violations`` list is itself the safe diagnostic
signal — an operator or CI pipeline can check
``bool(report.invariant_violations)`` the same way it already checks
``report.success``.

``assert_report_invariants(report)`` is the TEST-only strict counterpart —
it raises ``AssertionError`` (listing every violation) when the list is
non-empty. Production code must never call it; only tests that want to
"fail report construction loudly ... for invalid internal state" do.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.eval.report import RunReport


def check_report_invariants(report: "RunReport") -> list[str]:
    """Return every internal-consistency violation found in *report*.
    Never raises. Empty list means the report is internally consistent."""
    violations: list[str] = []

    # -- Structural self-consistency --------------------------------------
    if report.finding_count != len(report.findings):
        violations.append(
            f"finding_count ({report.finding_count}) does not match "
            f"len(findings) ({len(report.findings)})"
        )

    if report.completed_successfully and not report.completed:
        violations.append(
            "completed_successfully is True but completed is False "
            "(a successful engagement must have reached a terminal runtime state)"
        )

    # -- Objective / success reconciliation --------------------------------
    # "objective verified implies successful engagement"
    if report.objective_verified and not report.success:
        violations.append(
            "objective_verified is True but success is False — "
            "objective verification must imply engagement success"
        )
    # "benchmark success implies objective verified"
    if report.success and not report.objective_verified:
        violations.append(
            "success is True but objective_verified is False — "
            "benchmark success must imply the configured objective was verified"
        )

    # -- Access-validated fields internally consistent ---------------------
    access = report.access_summary or {}
    if access.get("validated") and not access.get("protocol"):
        violations.append(
            "access_summary.validated is True but access_summary.protocol is unset"
        )

    # -- Error counts reconcile with execution records ---------------------
    reported_failures = report.script_error_count + report.fixable_count + report.fundamental_count
    if reported_failures > 0 and not report.execution_diagnostics:
        violations.append(
            f"{reported_failures} failed turn(s) recorded (script_error/fixable/fundamental) "
            "but execution_diagnostics is empty — a report in this state cannot be diagnosed"
        )
    elif reported_failures > 0 and report.execution_diagnostics:
        non_success = sum(
            1 for d in report.execution_diagnostics
            if d.get("diagnostic_category") not in ("success", "")
        )
        if non_success == 0:
            violations.append(
                "failed turns were recorded but no execution_diagnostics entry "
                "reflects a non-success diagnostic_category"
            )

    # -- Planner selected-task counts reconcile with real executions -------
    # Catches the exact confirmed live-test defect: every planner_decisions
    # entry showing selected_task_count=0 while real executions occurred.
    if report.execution_diagnostics and report.planner_decisions:
        had_effective_task = any(
            int(d.get("selected_task_count", 0) or 0) > 0
            or int(d.get("fallback_task_count", 0) or 0) > 0
            for d in report.planner_decisions
        )
        if not had_effective_task:
            violations.append(
                "execution_diagnostics is non-empty (real executions occurred) but every "
                "planner_decisions entry shows zero selected AND zero fallback tasks"
            )

    return violations


def assert_report_invariants(report: "RunReport") -> None:
    """Test-only strict variant. Raises ``AssertionError`` listing every
    violation when ``check_report_invariants(report)`` is non-empty.
    Production code (``build_report()``) never calls this — see module
    docstring."""
    violations = check_report_invariants(report)
    if violations:
        bullet_list = "\n  - ".join(violations)
        raise AssertionError(
            f"RunReport failed {len(violations)} invariant(s):\n  - {bullet_list}"
        )
