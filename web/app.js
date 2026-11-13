(() => {
  "use strict";
  const state = { key: "", selectedImportAccepted: false };
  const $ = (id) => document.getElementById(id);
  const node = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = String(text ?? "—");
    return n;
  };
  const notice = (message, error = false) => {
    const n = $("notice");
    n.textContent = message;
    n.className = error ? "error" : "success";
    n.hidden = false;
  };
  const api = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    headers.set("X-API-Key", state.key);
    const r = await fetch(path, { ...options, headers, cache: "no-store" });
    if (!r.ok) {
      let message = "HTTP " + r.status;
      try {
        message = (await r.json()).detail || message;
      } catch {}
      throw Error(message);
    }
    return r.status === 204 ? null : r.json();
  };
  const connected = (on) => {
    $("connection").textContent = on ? "● Connected" : "● Not connected";
    $("connection").classList.toggle("connected", on);
    [
      "refresh-overview",
      "refresh-inventory",
      "refresh-audit",
      "sbom-submit",
      "product-submit", "release-submit", "product-sbom-submit",
      "product-load-imports",
      "run-assessment", "load-assessments",
    ].forEach((id) => ($(id).disabled = !on));
    $("run-assessment").disabled = !on || !state.selectedImportAccepted;
    $("load-assessments").disabled = !on || !state.selectedImportAccepted;
  };
  const view = (name) => {
    document
      .querySelectorAll(".view")
      .forEach((v) => (v.hidden = v.id !== "view-" + name));
    document
      .querySelectorAll(".nav")
      .forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    $("title").textContent = {
      overview: "Overview",
      inventory: "Device inventory",
      sbom: "SBOM analysis",
      audit: "Audit trail",
    }[name];
  };
  const run = async (fn) => {
    if (!state.key) return;
    try {
      await fn();
      notice("Data refreshed from the API.");
    } catch (e) {
      notice("Request failed: " + e.message, true);
    }
  };
  let devices = [];
  const deviceRow = (parent, d) => {
    const row = node("div", "device-row"),
      b = node("button", ""),
      left = node("span", ""),
      name = node("b", "", d.device_id),
      sub = node(
        "small",
        "",
        d.manufacturer + " · " + d.model + " · FW " + d.firmware_version,
      );
    left.append(name, sub);
    b.append(left);
    b.addEventListener("click", () => select(d.device_id));
    row.append(b, node("span", "pill", d.support_until || "Lifecycle unknown"));
    parent.append(row);
  };
  const loadDevices = async () => {
    devices = await api("/devices");
    $("device-count").textContent = devices.length;
    for (const id of ["devices", "recent"]) {
      const target = $(id);
      target.replaceChildren();
      if (!devices.length)
        target.append(node("p", "empty", "No devices registered."));
      else
        devices
          .slice(0, id === "recent" ? 5 : devices.length)
          .forEach((d) => deviceRow(target, d));
    }
    $("m-devices").textContent = devices.length;
  };
  const select = async (id) => {
    try {
      const [d, p, v] = await Promise.all([
        api("/devices/" + encodeURIComponent(id)),
        api("/devices/" + encodeURIComponent(id) + "/posture"),
        api("/devices/" + encodeURIComponent(id) + "/vulnerabilities"),
      ]);
      const root = $("detail");
      root.replaceChildren();
      const head = node("div", "detail-title"),
        title = node("div", "");
      title.append(
        node("h3", "", d.device_id),
        node("p", "", d.manufacturer + " · " + d.model),
      );
      const report = node("button", "secondary", "Download JSON report");
      report.addEventListener("click", () => download(id));
      head.append(title, report);
      root.append(head);
      const grid = node("div", "detail-grid");
      [
        ["Firmware", d.firmware_version],
        ["Support until", d.support_until],
        ["Highest risk", p.highest_risk],
        ["Evidence coverage", p.evidence_coverage],
      ].forEach(([k, val]) => {
        const f = node("div", "");
        f.append(node("small", "", k), node("b", "", val || "Unknown"));
        grid.append(f);
      });
      root.append(grid, node("h4", "subhead", "Security controls"));
      (p.controls || []).forEach((c) => {
        const r = node("div", "control");
        r.append(
          node("span", "", c.control),
          node(
            "span",
            "state state-" + String(c.status).replace(/[^a-z_]/g, ""),
            c.status,
          ),
        );
        root.append(r);
      });
      root.append(
        node("h4", "subhead", "Vulnerability findings (" + v.length + ")"),
      );
      if (!v.length)
        root.append(
          node(
            "p",
            "empty",
            "No findings recorded. This is not proof of absence of vulnerabilities.",
          ),
        );
      v.forEach((x) => {
        const r = node("div", "control");
        r.append(
          node("span", "", x.vuln_id + " · " + x.component + " " + x.version),
          node("span", "", x.severity + " / " + x.status),
        );
        root.append(r);
        const form = node("form", "triage-form"),
          status = node("select", ""),
          reason = node("input", ""),
          submit = node("button", "secondary", "Save triage");
        [
          "open",
          "in_progress",
          "fixed",
          "accepted_risk",
          "not_affected",
        ].forEach((value) => {
          const option = node("option", "", value);
          option.value = value;
          option.selected = value === x.status;
          status.append(option);
        });
        status.setAttribute("aria-label", "Triage status");
        reason.placeholder = "Justification (at least 10 characters)";
        reason.minLength = 10;
        reason.maxLength = 1000;
        reason.required = true;
        reason.setAttribute("aria-label", "Triage justification");
        form.append(status, reason, submit);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          try {
            await api("/vulnerabilities/" + encodeURIComponent(x.id), {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                status: status.value,
                justification: reason.value.trim(),
              }),
            });
            notice("Triage decision recorded in the audit trail.");
            await select(id);
          } catch (error) {
            notice("Triage failed: " + error.message, true);
          }
        });
        root.append(form);
      });
      view("inventory");
    } catch (e) {
      notice("Device load failed: " + e.message, true);
    }
  };
  const download = async (id) => {
    try {
      const data = await api(
          "/devices/" + encodeURIComponent(id) + "/report?format=json",
        ),
        url = URL.createObjectURL(
          new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          }),
        ),
        a = node("a");
      a.href = url;
      a.download = id + "-security-report.json";
      document.body.append(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      notice("Report failed: " + e.message, true);
    }
  };
  const overview = async () => {
    await loadDevices();
    const all = (
        await Promise.all(
          devices.map((d) =>
            api(
              "/devices/" +
                encodeURIComponent(d.device_id) +
                "/vulnerabilities",
            ).catch(() => []),
          ),
        )
      ).flat(),
      open = all.filter((x) => !["fixed", "not_affected"].includes(x.status)),
      high = open.filter((x) =>
        ["high", "critical"].includes(String(x.severity).toLowerCase()),
      );
    $("m-findings").textContent = open.length;
    $("m-high").textContent = high.length;
    try {
      const a = await api("/audit/verify");
      $("m-audit").textContent = a.valid ? "Valid" : "Broken";
      $("m-audit-detail").textContent = a.entries + " recorded events";
    } catch {
      $("m-audit").textContent = "Unknown";
      $("m-audit-detail").textContent = "Verification unavailable";
    }
  };
  const audit = async () => {
    const [events, v] = await Promise.all([
      api("/audit"),
      api("/audit/verify"),
    ]);
    $("audit-count").textContent = events.length;
    $("audit-state").textContent = v.valid
      ? "Chain valid"
      : "Broken at entry " + v.broken_at_id;
    $("audit-state").classList.toggle("broken", !v.valid);
    $("audit-summary").textContent =
      v.entries + " entries verified · tamper-evident, not immutable";
    $("audit-icon").textContent = v.valid ? "✓" : "!";
    const body = $("audit-rows");
    body.replaceChildren();
    if (!events.length) {
      const tr = node("tr", ""),
        td = node("td", "empty", "No audit events.");
      td.colSpan = 6;
      tr.append(td);
      body.append(tr);
    }
    events.forEach((e) => {
      const tr = node("tr", "");
      [
        e.id,
        e.ts,
        e.actor,
        e.action,
        e.entity,
        String(e.hash || "").slice(0, 16) + "…",
      ].forEach((x) => tr.append(node("td", "", x)));
      body.append(tr);
    });
  };
  $("connect-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const candidate = $("api-key").value.trim();
    if (!candidate) return;
    state.key = candidate;
    try {
      await api("/devices");
      $("connect-panel").hidden = true;
      $("connect-toggle").textContent = "Disconnect";
      connected(true);
      await overview();
      notice("Connected. Live API data loaded.");
    } catch (err) {
      state.key = "";
      connected(false);
      notice("Connection failed: " + err.message, true);
    }
  });
  $("connect-toggle").addEventListener("click", () => {
    if (state.key) {
      state.key = "";
      state.selectedImportAccepted = false;
      $("assessment-import-id").value = "";
      $("api-key").value = "";
      $("connect-panel").hidden = false;
      $("connect-toggle").textContent = "Connect API";
      connected(false);
      ["m-devices", "m-findings", "m-high", "m-audit"].forEach(
        (id) => ($(id).textContent = "—"),
      );
      ["devices", "recent", "detail", "audit-rows"].forEach((id) =>
        $(id).replaceChildren(node("p", "empty", "Connect to load data.")),
      );
      notice("Disconnected. API key cleared from page memory.");
    } else {
      $("connect-panel").hidden = false;
      $("api-key").focus();
    }
  });
  document.querySelectorAll("[data-view]").forEach((b) =>
    b.addEventListener("click", () => {
      view(b.dataset.view);
      if (!state.key) return;
      if (b.dataset.view === "inventory") run(loadDevices);
      if (b.dataset.view === "audit") run(audit);
    }),
  );
  document
    .querySelectorAll("[data-go]")
    .forEach((b) => b.addEventListener("click", () => view(b.dataset.go)));
  $("refresh-overview").addEventListener("click", () => run(overview));
  $("refresh-inventory").addEventListener("click", () => run(loadDevices));
  $("refresh-audit").addEventListener("click", () => run(audit));
  $("sbom-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = $("sbom-file").files[0],
      id = $("sbom-device").value.trim();
    if (!f || !state.key) return;
    if (f.size > 2097152) {
      notice("File exceeds the 2 MiB upload limit.", true);
      return;
    }
    try {
      const result = await api("/devices/" + encodeURIComponent(id) + "/sbom", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: await f.text(),
        }),
        box = $("sbom-result");
      box.replaceChildren(
        node("b", "", "Import completed"),
        node(
          "p",
          "",
          result.components +
            " components processed · " +
            result.new_findings +
            " new findings",
        ),
      );
      box.hidden = false;
      notice("SBOM processed. Review findings in inventory.");
    } catch (err) {
      notice("SBOM import failed: " + err.message, true);
    }
  });

  const productResult = (id, payload) => {
    const box = $(id);
    box.replaceChildren(node("b", "", payload.title));
    const details = Object.entries(payload.values).map(([key, value]) => key + ": " + value).join(" · ");
    box.append(node("p", "", details));
    box.hidden = false;
  };
  $("product-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api("/products", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ manufacturer: $("product-manufacturer").value.trim(),
          product_name: $("product-name").value.trim(),
          external_reference: $("product-reference").value.trim() || null }) });
      $("product-id").value = result.id;
      productResult("product-result", { title: "Product registered", values: { ID: result.id, Manufacturer: result.manufacturer, Product: result.product_name } });
      notice("Product registered through the DeviceTrust API.");
    } catch (error) { notice("Product registration failed: " + error.message, true); }
  });
  $("release-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const productId = $("product-id").value;
    try {
      const result = await api("/products/" + encodeURIComponent(productId) + "/releases", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: $("release-version").value.trim(),
          hardware_revision: $("release-hardware").value.trim() || null,
          release_reference: $("release-reference").value.trim() || null }) });
      $("product-release-id").value = result.id;
      $("imports-release-id").value = result.id;
      productResult("release-result", { title: "Release registered", values: { ID: result.id, "Product ID": result.product_id, Version: result.version } });
      notice("Product release registered through the DeviceTrust API.");
    } catch (error) { notice("Release registration failed: " + error.message, true); }
  });
  $("product-sbom-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = $("product-sbom-file").files[0], releaseId = $("product-release-id").value;
    if (!file) return;
    if (file.size > 2097152) { notice("File exceeds the 2 MiB upload limit.", true); return; }
    try {
      const sourceType = $("product-source-type").value;
      const sourceReference = $("product-source-reference").value.trim();
      const query = new URLSearchParams({ source_type: sourceType });
      if (sourceReference) query.set("source_reference", sourceReference);
      const result = await api("/product-releases/" + encodeURIComponent(releaseId) + "/sbom?" + query.toString(), {
        method: "POST", headers: { "Content-Type": "application/json" }, body: await file.text() });
      $("assessment-import-id").value = result.id;
      state.selectedImportAccepted = result.status === "accepted";
      $("run-assessment").disabled = !state.key || !state.selectedImportAccepted;
      $("load-assessments").disabled = !state.key || !state.selectedImportAccepted;
      productResult("product-import-result", { title: "Product SBOM imported", values: {
        "Import ID": result.id, Status: result.status, Components: result.component_count,
        "SHA-256": String(result.content_sha256 || "").slice(0, 16) + "…" } });
      $("imports-release-id").value = releaseId;
      await loadProductImports();
      notice("Product SBOM imported. Review its validation status before assessment.");
    } catch (error) { notice("Product SBOM import failed: " + error.message, true); }
  });
  const loadProductImports = async () => {
    const releaseId = $("imports-release-id").value.trim();
    if (!releaseId) { notice("Enter a product release ID.", true); return; }
    try {
      const imports = await api("/product-releases/" + encodeURIComponent(releaseId) + "/sbom");
      const root = $("product-imports"); root.replaceChildren();
      if (!imports.length) root.append(node("p", "empty", "No SBOM imports for this release."));
      imports.forEach((item) => {
        const row = node("div", "device-row"), left = node("span", "");
        left.append(node("b", "", "Import #" + item.id + " · " + item.status),
          node("small", "", item.component_count + " components · " + item.format + " · " + item.content_sha256.slice(0, 16) + "…"));
        const choose = node("button", "secondary", "Select");
        choose.disabled = item.status !== "accepted";
        choose.title = item.status === "accepted" ? "Select accepted import" : "Only accepted imports can be assessed";
        choose.addEventListener("click", () => {
          $("assessment-import-id").value = item.id;
          state.selectedImportAccepted = true;
          $("run-assessment").disabled = !state.key;
          $("load-assessments").disabled = !state.key;
          $("product-findings").hidden = true;
        });
        row.append(left, choose); root.append(row);
      });
      notice(imports.length + " product SBOM import(s) loaded.");
    } catch (error) { notice("Import history failed: " + error.message, true); }
  };
  $("product-load-imports").addEventListener("click", loadProductImports);
  $("run-assessment").addEventListener("click", async () => {
    const importId = $("assessment-import-id").value.trim();
    if (!importId) return;
    try {
      const key = crypto.randomUUID();
      const result = await api("/sbom/imports/" + encodeURIComponent(importId) + "/assessments", {
        method: "POST", headers: { "Idempotency-Key": key } });
      productResult("product-findings", { title: "Assessment completed", values: {
        "Assessment ID": result.id, Status: result.status, Components: result.component_count,
        Findings: result.finding_count, Created: result.created } });
      $("product-findings").hidden = false;
      await loadProductAssessments();
      notice("Assessment request completed. Inspect its findings and enrichment metadata.");
    } catch (error) { notice("Assessment failed: " + error.message, true); }
  });
  const loadProductAssessments = async () => {
    const importId = $("assessment-import-id").value.trim();
    if (!importId) { notice("Enter an SBOM import ID.", true); return; }
    try {
      const rows = await api("/sbom/imports/" + encodeURIComponent(importId) + "/assessments");
      const root = $("product-assessments"); root.replaceChildren();
      if (!rows.length) root.append(node("p", "empty", "No assessments recorded."));
      rows.forEach((item) => {
        const row = node("div", "device-row"), left = node("span", "");
        left.append(node("b", "", "Assessment #" + item.id + " · " + item.status),
          node("small", "", item.component_count + " components · " + item.finding_count + " findings · " + (item.completed_at || item.started_at)));
        const choose = node("button", "secondary", "View findings");
        choose.addEventListener("click", async () => {
          try {
            const findings = await api("/sbom/imports/" + encodeURIComponent(importId) + "/assessments/" + encodeURIComponent(item.id) + "/findings");
            const box = $("product-findings"); box.replaceChildren(node("b", "", "Assessment #" + item.id + " findings (" + findings.length + ")"));
            if (!findings.length) box.append(node("p", "", "No findings were returned for this assessment."));
            findings.forEach((finding) => box.append(node("p", "", [finding.vuln_id, finding.severity, finding.source, "Component #" + finding.sbom_component_id, finding.applicability].filter(Boolean).join(" · "))));
            box.hidden = false;
          } catch (error) { notice("Findings could not be loaded: " + error.message, true); }
        });
        row.append(left, choose); root.append(row);
      });
      notice(rows.length + " assessment(s) loaded.");
    } catch (error) { notice("Assessment history failed: " + error.message, true); }
  };
  $("assessment-import-id").addEventListener("input", () => {
    state.selectedImportAccepted = false;
    $("run-assessment").disabled = true;
    $("load-assessments").disabled = true;
  });
  $("load-assessments").addEventListener("click", loadProductAssessments);

  view("overview");
  connected(false);
})();
