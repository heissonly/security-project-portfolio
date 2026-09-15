const button = document.querySelector("#run-gate");
if (button) {
  button.addEventListener("click", () => {
    const rows = [...document.querySelectorAll(".control-row")];
    const isHighRisk = (row) => {
      const severity = row.querySelector("[data-severity]").value;
      const accepted = row.querySelector("[data-accepted]").checked;
      return ["high", "critical"].includes(severity) && !accepted;
    };
    const fixableEl = (row) => row.querySelector("[data-fixable]");
    const blockers = rows.filter((row) => isHighRisk(row) && (!fixableEl(row) || fixableEl(row).checked));
    const tracked = rows.filter((row) => isHighRisk(row) && fixableEl(row) && !fixableEl(row).checked);
    const result = document.querySelector("#gate-result");
    const blocked = blockers.length > 0;
    result.className = `result ${blocked ? "fail" : "pass"}`;
    let text = blocked
      ? `BLOCKED — ${blockers.length} open, fixable high/critical finding${blockers.length === 1 ? "" : "s"}.`
      : "PASSED — no unaccepted, fixable high/critical findings.";
    if (tracked.length > 0) {
      text += ` ${tracked.length} unfixed-upstream finding${tracked.length === 1 ? "" : "s"} tracked, not blocking.`;
    }
    result.textContent = text;
  });
}

