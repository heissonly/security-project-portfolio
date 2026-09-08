const labData = {
  D1: {
    source: "SigninLogs", threshold: "≥6 failures, ≥3 users, one IP", attack: "T1110.003",
    columns: ["ip", "user", "result"],
    tp: [
      { ip: "203.0.113.10", user: "alice@lab.invalid", result: "50126" },
      { ip: "203.0.113.10", user: "bob@lab.invalid", result: "50126" },
      { ip: "203.0.113.10", user: "carol@lab.invalid", result: "50126" },
      { ip: "203.0.113.10", user: "alice@lab.invalid", result: "50126" },
      { ip: "203.0.113.10", user: "bob@lab.invalid", result: "50126" },
      { ip: "203.0.113.10", user: "carol@lab.invalid", result: "50126" }
    ],
    fp: Array.from({ length: 6 }, () => ({ ip: "203.0.113.20", user: "alice@lab.invalid", result: "50126" })),
    evaluate(events) {
      const failed = events.filter((event) => event.result === "50126");
      return failed.length >= 6 && new Set(failed.map((event) => event.user)).size >= 3 && new Set(failed.map((event) => event.ip)).size === 1;
    },
    rationale: (events) => `${events.length} failed sign-ins across ${new Set(events.map((event) => event.user)).size} distinct user(s).`,
    kql: `SigninLogs
| where ResultType != 0
| summarize Failures=count(), Users=dcount(UserPrincipalName)
  by IPAddress, bin(TimeGenerated, 10m)
| where Failures >= 6 and Users >= 3`
  },
  D2: {
    source: "AuditLogs", threshold: "Successful role-member addition", attack: "T1098.003",
    columns: ["operation", "result", "role"],
    tp: [{ operation: "Add member to role", result: "success", role: "Global Reader" }],
    fp: [{ operation: "Remove member from role", result: "success", role: "Global Reader" }],
    evaluate: (events) => events.some((event) => event.operation === "Add member to role" && event.result === "success"),
    rationale: (events) => `Observed “${events[0].operation}” with result “${events[0].result}”.`,
    kql: `AuditLogs
| where OperationName has "Add member to role"
| where Result =~ "success"
| project TimeGenerated, InitiatedBy, TargetResources`
  },
  D3: {
    source: "Event via AMA/DCR", threshold: "Event 4104 + suspicious term", attack: "T1059.001",
    columns: ["event_id", "event_log", "script"],
    tp: [{ event_id: 4104, event_log: "PowerShell/Operational", script: "powershell -EncodedCommand VwByAGkAdABlAC0..." }],
    fp: [{ event_id: 4104, event_log: "PowerShell/Operational", script: "Get-Process | Select-Object Name, Id" }],
    evaluate: (events) => events.some((event) => event.event_id === 4104 && /encodedcommand/i.test(event.script)),
    rationale: (events) => `Event ${events[0].event_id}; encoded-command marker ${/encodedcommand/i.test(events[0].script) ? "present" : "absent"}.`,
    kql: `Event
| where EventLog == "Microsoft-Windows-PowerShell/Operational"
| where EventID in (4103, 4104)
| where RenderedDescription has_any ("EncodedCommand", "FromBase64String")`
  },
  D4: {
    source: "AuditLogs", threshold: "Application password credential change", attack: "T1098.001",
    columns: ["operation", "result", "property"],
    tp: [{ operation: "Update application", result: "success", property: "PasswordCredentials" }],
    fp: [{ operation: "Update application", result: "success", property: "DisplayName" }],
    evaluate: (events) => events.some((event) => event.operation === "Update application" && event.result === "success" && event.property === "PasswordCredentials"),
    rationale: (events) => `Application update changed “${events[0].property}”.`,
    kql: `AuditLogs
| where OperationName =~ "Update application"
| where Result =~ "success"
| where tostring(TargetResources) has "PasswordCredentials"`
  }
};

let activeRule = "D1";
let activeFixture = "tp";
const byId = (id) => document.getElementById(id);

function renderFixture() {
  const rule = labData[activeRule];
  const events = rule[activeFixture];
  byId("rule-source").textContent = rule.source;
  byId("rule-threshold").textContent = rule.threshold;
  byId("rule-attack").textContent = rule.attack;
  byId("event-count").textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
  byId("event-head").innerHTML = `<tr>${rule.columns.map((column) => `<th>${column.replace("_", " ")}</th>`).join("")}</tr>`;
  byId("event-body").innerHTML = events.map((event) => `<tr>${rule.columns.map((column) => `<td>${String(event[column])}</td>`).join("")}</tr>`).join("");
  byId("kql-code").textContent = rule.kql;
  const result = byId("detection-result");
  result.className = "detection-result idle";
  result.innerHTML = '<div class="result-state"><span class="result-icon">○</span><div><small>ANALYSIS STATUS</small><strong>Ready to evaluate</strong></div></div><p>Select a fixture and run the local rule.</p>';
}

document.querySelectorAll("[data-rule]").forEach((button) => button.addEventListener("click", () => {
  activeRule = button.dataset.rule;
  document.querySelectorAll("[data-rule]").forEach((item) => item.classList.toggle("active", item === button));
  renderFixture();
}));

document.querySelectorAll("[data-fixture]").forEach((button) => button.addEventListener("click", () => {
  activeFixture = button.dataset.fixture;
  document.querySelectorAll("[data-fixture]").forEach((item) => item.classList.toggle("active", item === button));
  renderFixture();
}));

byId("run-detection").addEventListener("click", () => {
  const runButton = byId("run-detection");
  const result = byId("detection-result");
  runButton.disabled = true;
  result.className = "detection-result running";
  result.innerHTML = `<div class="result-state"><span class="result-icon">◌</span><div><small>ANALYSIS STATUS</small><strong>Evaluating fixture…</strong></div></div><p>Applying ${activeRule} decision boundary to synthetic events.</p>`;
  window.setTimeout(() => {
    const rule = labData[activeRule];
    const events = rule[activeFixture];
    const alerted = rule.evaluate(events);
    const expected = activeFixture === "tp";
    result.className = `detection-result ${alerted ? "alert" : "clean"}`;
    result.innerHTML = `<div class="result-state"><span class="result-icon">${alerted ? "!" : "✓"}</span><div><small>${alerted ? "ALERT CONDITION" : "BELOW BOUNDARY"}</small><strong>${alerted ? "Rule would create an alert" : "Rule suppresses this fixture"}</strong></div><span class="test-match">${alerted === expected ? "EXPECTED RESULT" : "CHECK FAILED"}</span></div><p>${rule.rationale(events)}</p>`;
    runButton.disabled = false;
  }, 650);
});

renderFixture();
