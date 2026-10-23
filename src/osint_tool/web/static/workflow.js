(() => {
  "use strict";

  const root = document.querySelector("#workflow");
  const progressTitle = document.querySelector("#progress-title");
  const progressDetail = document.querySelector("#progress-detail");
  const progressFill = document.querySelector("#progress-fill");
  const progressBar = document.querySelector('[role="progressbar"]');
  const moduleProgress = document.querySelector("#module-progress");
  const moduleList = document.querySelector("#module-list");
  const progressError = document.querySelector("#progress-error");
  const reviewCard = document.querySelector("#review-card");
  const metrics = document.querySelector("#metrics");
  const checkBody = document.querySelector("#checks-body");
  const findingsBody = document.querySelector("#findings-body");
  const relationsBody = document.querySelector("#relations-body");
  const filterCount = document.querySelector("#filter-count");
  const findingsCount = document.querySelector("#findings-count");
  const queryInput = document.querySelector("#query");
  const moduleFilter = document.querySelector("#module-filter");
  const reportForm = document.querySelector("#report-form");
  const generateButton = document.querySelector("#generate-report");
  const reportError = document.querySelector("#report-error");
  const reportReady = document.querySelector("#report-ready");
  const loadMoreButton = document.querySelector("#load-more");
  const findingsLoadMoreButton = document.querySelector("#findings-load-more");
  const pageSize = 50;
  let checks = [];
  let findings = [];
  let relations = [];
  let filteredChecks = [];
  let filteredFindings = [];
  let shownCount = 0;
  let shownFindingsCount = 0;
  let pollDelay = 700;

  function setProgress(value) {
    const percent = Math.max(0, Math.min(100, value));
    progressFill.classList.remove("indeterminate");
    progressFill.style.width = `${percent}%`;
    progressBar.setAttribute("aria-valuenow", String(Math.round(percent)));
  }

  function showError(element, message) {
    element.textContent = message;
    element.hidden = false;
  }

  function renderModuleList(modules, currentModule) {
    moduleList.replaceChildren();
    for (const module of modules) {
      const item = document.createElement("li");
      item.textContent = module.name;
      if (module.status) {
        const status = document.createElement("span");
        status.className = `status ${module.status}`;
        status.textContent = `${module.status} · ${module.findings} hallazgos`;
        item.append(status);
      } else if (module.name === currentModule) {
        const status = document.createElement("span");
        status.className = "status";
        status.textContent = "consultando…";
        item.append(status);
      } else {
        const status = document.createElement("span");
        status.className = "status";
        status.textContent = "pendiente";
        item.append(status);
      }
      moduleList.append(item);
    }
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, { cache: "no-store", ...options });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `La solicitud falló (HTTP ${response.status}).`);
    }
    return payload;
  }

  async function loadResults() {
    const data = await fetchJson(root.dataset.dataUrl);
    checks = data.source_checks;
    findings = data.finding_items;
    relations = data.relation_items;
    for (const module of data.modules) {
      const option = document.createElement("option");
      option.value = module.name;
      option.textContent = module.name;
      moduleFilter.append(option);
    }
    const countByStatus = Object.fromEntries(
      ["found", "not_found", "inconclusive", "error"].map((status) => [
        status,
        checks.filter((check) => check.status === status).length,
      ]),
    );
    metrics.replaceChildren();
    const totals = [
      ["Módulos", data.modules.length],
      ["Hallazgos", data.findings],
      ["Relaciones", data.relations],
      ["Comprobaciones", checks.length],
      ["Encontrados", countByStatus.found],
      ["Inconclusos / errores", countByStatus.inconclusive + countByStatus.error],
    ];
    for (const [label, value] of totals) {
      const metric = document.createElement("div");
      metric.className = "metric";
      const strong = document.createElement("strong");
      strong.textContent = String(value);
      const caption = document.createElement("span");
      caption.textContent = label;
      metric.append(strong, caption);
      metrics.append(metric);
    }
    applyFilters();
    document.querySelector("#progress-card").hidden = true;
    reviewCard.hidden = false;
  }

  async function poll() {
    try {
      const state = await fetchJson(root.dataset.statusUrl);
      const done = state.completed_modules;
      const total = state.total_modules;
      if (state.status === "failed") {
        progressTitle.textContent = "La búsqueda no pudo completarse.";
        progressDetail.textContent = "No se generó ningún informe.";
        showError(progressError, state.error);
        return;
      }

      if (state.status === "complete") {
        setProgress(100);
        progressTitle.textContent = "Consultas completadas";
        progressDetail.textContent = `${done} de ${total} módulos procesados.`;
        renderModuleList(state.modules, null);
        await loadResults();
        return;
      }

      progressTitle.textContent = state.status === "queued"
        ? "En cola"
        : `Consultando módulos (${done}/${total})`;
      if (state.current_module && state.current_total > 0) {
        const percent = Math.round(state.current_completed / state.current_total * 100);
        moduleProgress.textContent =
          `${state.current_module}: ${state.current_completed}/${state.current_total} sitios (${percent}%).`;
        setProgress(total ? (done + state.current_completed / state.current_total) / total * 100 : 0);
      } else if (state.current_module) {
        moduleProgress.textContent = `Consultando fuente: ${state.current_module}.`;
        progressFill.style.width = "";
        progressFill.classList.add("indeterminate");
      } else {
        moduleProgress.textContent = "Preparando la siguiente fuente…";
        setProgress(total ? done / total * 100 : 0);
      }
      progressDetail.textContent = `${done} de ${total} módulos finalizados.`;
      renderModuleList(
        [...state.modules, ...(state.current_module ? [{ name: state.current_module }] : [])],
        state.current_module,
      );
      window.setTimeout(poll, pollDelay);
      pollDelay = Math.min(1800, pollDelay + 100);
    } catch (error) {
      showError(progressError, error.message);
    }
  }

  function selectedStatuses() {
    return new Set(
      [...reportForm.querySelectorAll('input[name="statuses"]:checked')]
        .map((input) => input.value),
    );
  }

  function appendProfileLink(row, check) {
    if (!check.profile_url) return;
    try {
      const linkUrl = new URL(check.profile_url);
      if (linkUrl.protocol !== "https:" && linkUrl.protocol !== "http:") return;
      const link = document.createElement("a");
      link.href = linkUrl.href;
      link.rel = "noreferrer noopener";
      link.target = "_blank";
      link.textContent = "Ver perfil";
      row.append(link);
    } catch {
      return;
    }
  }

  function renderNextPage() {
    const next = filteredChecks.slice(shownCount, shownCount + pageSize);
    for (const check of next) {
      const row = document.createElement("tr");
      for (const value of [check.module, check.source, check.status, check.detail]) {
        const cell = document.createElement("td");
        cell.textContent = value || "—";
        row.append(cell);
      }
      appendProfileLink(row.cells[3], check);
      checkBody.append(row);
    }
    shownCount += next.length;
    loadMoreButton.hidden = shownCount >= filteredChecks.length;
  }

  function renderNextFindingsPage() {
    const next = filteredFindings.slice(shownFindingsCount, shownFindingsCount + pageSize);
    for (const finding of next) {
      const row = document.createElement("tr");
      const values = [
        finding.module,
        finding.type,
        finding.value,
        finding.record_type ? `${finding.source} ${finding.record_type}` : finding.source,
        finding.detail,
        Number(finding.confidence).toFixed(2),
      ];
      for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = value || "—";
        row.append(cell);
      }
      findingsBody.append(row);
    }
    shownFindingsCount += next.length;
    findingsLoadMoreButton.hidden = shownFindingsCount >= filteredFindings.length;
  }

  function matchesQuery(values, query) {
    return !query || values.join(" ").toLocaleLowerCase().includes(query);
  }

  function checkMatchesFinding(check, finding) {
    return check.source === finding.source
      || (finding.module === "domain"
        && finding.source === "DNS"
        && check.source === `DNS ${finding.record_type}`);
  }

  function applyFilters() {
    const statuses = selectedStatuses();
    const query = queryInput.value.trim().toLocaleLowerCase();
    const module = moduleFilter.value;
    const relevantFindings = findings.filter((finding) => !module || finding.module === module);
    filteredFindings = relevantFindings.filter((finding) => {
      const matchingChecks = checks.filter(
        (check) => check.module === finding.module && checkMatchesFinding(check, finding),
      );
      const foundAndSelected = matchingChecks.length === 0
        || (statuses.has("found") && matchingChecks.some((check) => check.status === "found"));
      return foundAndSelected && matchesQuery(
        [finding.module, finding.type, finding.value, finding.source, finding.detail],
        query,
      );
    });
    filteredChecks = checks.filter((check) => {
      if (!statuses.has(check.status) || (module && check.module !== module)) return false;
      if (matchesQuery([check.source, check.detail], query)) return true;
      return relevantFindings.some(
        (finding) =>
          finding.module === check.module
          && checkMatchesFinding(check, finding)
          && matchesQuery(
            [finding.module, finding.type, finding.value, finding.source, finding.detail],
            query,
          ),
      );
    });

    shownCount = 0;
    checkBody.replaceChildren();
    filterCount.textContent =
      `Mostrando 0 de ${filteredChecks.length} comprobaciones filtradas (${checks.length} en total).`;
    renderNextPage();
    filterCount.textContent =
      `Mostrando ${shownCount} de ${filteredChecks.length} comprobaciones filtradas (${checks.length} en total).`;

    shownFindingsCount = 0;
    findingsBody.replaceChildren();
    findingsCount.textContent =
      `Mostrando 0 de ${filteredFindings.length} hallazgos (${findings.length} en total).`;
    renderNextFindingsPage();
    findingsCount.textContent =
      `Mostrando ${shownFindingsCount} de ${filteredFindings.length} hallazgos (${findings.length} en total).`;

    relationsBody.replaceChildren();
    const moduleSources = new Set(
      filteredFindings.map((finding) => finding.source),
    );
    for (const relation of relations) {
      const evidence = relation.evidence.join(", ");
      const relatedToVisibleFinding = relation.evidence.includes("input")
        || relation.evidence.some((source) => moduleSources.has(source));
      const relatedToQuery = matchesQuery(
        [relation.source, relation.target, relation.label, evidence],
        query,
      );
      if (!relatedToVisibleFinding || !relatedToQuery) continue;
      const row = document.createElement("tr");
      for (const value of [
        relation.source,
        relation.target,
        relation.label,
        evidence || "No especificada",
        Number(relation.confidence).toFixed(2),
      ]) {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      }
      relationsBody.append(row);
    }
  }

  reportForm.addEventListener("change", applyFilters);
  queryInput.addEventListener("input", applyFilters);
  moduleFilter.addEventListener("change", applyFilters);
  loadMoreButton.addEventListener("click", renderNextPage);
  findingsLoadMoreButton.addEventListener("click", renderNextFindingsPage);
  reportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    reportError.hidden = true;
    reportReady.hidden = true;
    generateButton.disabled = true;
    generateButton.textContent = "Generando informe…";
    try {
      const payload = await fetchJson(root.dataset.reportUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(new FormData(reportForm)),
      });
      document.querySelector("#report-link").href = payload.report_url;
      document.querySelector("#report-files").textContent =
        `Archivos: ${payload.files.join(", ")}`;
      reportReady.hidden = false;
    } catch (error) {
      showError(reportError, error.message);
    } finally {
      generateButton.disabled = false;
      generateButton.textContent = "Generar informe";
    }
  });

  poll();
})();
