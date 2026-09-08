const button = document.querySelector("#run-gate");
if (button) {
  button.addEventListener("click", () => {
    const rows = [...document.querySelectorAll(".control-row")];
    const blockers = rows.filter((row) => {
      const severity = row.querySelector("[data-severity]").value;
      const accepted = row.querySelector("[data-accepted]").checked;
      return ["high", "critical"].includes(severity) && !accepted;
    });
    const result = document.querySelector("#gate-result");
    const blocked = blockers.length > 0;
    result.className = `result ${blocked ? "fail" : "pass"}`;
    result.textContent = blocked
      ? `BLOCKED — ${blockers.length} open high/critical finding${blockers.length === 1 ? "" : "s"}.`
      : "PASSED — no unaccepted high/critical findings.";
  });
}

