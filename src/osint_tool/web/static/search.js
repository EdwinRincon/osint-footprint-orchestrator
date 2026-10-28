(() => {
  "use strict";

  const form = document.querySelector('form[action="/"]');
  const fields = [...form.querySelectorAll(".field input")];
  const modules = [...document.querySelectorAll(".analysis-item")];
  const offlineToggle = form.querySelector("#offline");
  const phoneField = form.querySelector("#phone");
  const phoneRegion = form.querySelector("#phone_region");
  const phoneRegionContainer = phoneRegion.closest(".field");
  const privacyStatus = document.querySelector("#privacy-status");
  const sourceSettings = document.querySelector(".source-settings");
  const sourceSummary = document.querySelector("#source-settings-summary");
  const noApplicableSources = document.querySelector("#no-applicable-sources");
  let previouslyApplicable = new Set();

  function updatePlan(event) {
    const offline = offlineToggle.checked;
    const provided = new Set(
      fields
        .filter((field) => field.id !== "phone_region" && field.value.trim())
        .map((field) => field.id),
    );
    const applicableNow = new Set();
    let addedApplicableSources = false;
    phoneRegionContainer.hidden = !phoneField.value.trim() || phoneField.value.trim().startsWith("+");

    for (const item of modules) {
      const accepts = item.dataset.accepts.split(" ");
      const applicable = accepts.some((field) => provided.has(field));
      const network = item.dataset.network === "true";
      const toggle = item.querySelector('input[type="checkbox"]');
      if (applicable) {
        applicableNow.add(item);
        if (!offline && !previouslyApplicable.has(item) && network) {
          toggle.checked = true;
          addedApplicableSources = true;
        }
      }

      item.hidden = !applicable;
      const optional = item.dataset.optional === "true";
      if (toggle && network) {
        toggle.disabled = offline;
      }
      if (event?.target === offlineToggle && !offline && applicable && network) {
        toggle.checked = true;
        sourceSettings.open = true;
      }
      const active =
        applicable && (!network ? (!optional || toggle.checked) : (!offline && toggle.checked));
      const state = item.querySelector(".analysis-state");

      item.dataset.active = String(active);
      if (network && offline) {
        state.textContent = "Bloqueada por modo privado";
      } else if (network && !toggle.checked) {
        state.textContent = "No se consultará";
      } else if (optional && !toggle.checked) {
        state.textContent = "Desactivada";
      } else {
        state.textContent = offline ? "Lista para análisis local" : "Se consultará";
      }
    }

    if (addedApplicableSources) {
      sourceSettings.open = true;
    }
    previouslyApplicable = applicableNow;
    const applicableCount = applicableNow.size;
    noApplicableSources.hidden = applicableCount > 0;
    const selectedCount = modules.filter(
      (item) => applicableNow.has(item) && item.querySelector('input[type="checkbox"]')?.checked,
    ).length;
    if (applicableCount) {
      const state = offline
        ? `${applicableCount} compatibles; desactivadas`
        : `${selectedCount} de ${applicableCount} activadas`;
      sourceSummary.textContent = `Fuentes externas (${state})`;
    } else {
      sourceSummary.textContent = offline
        ? "Fuentes externas (desactivadas)"
        : "Sin fuentes compatibles";
    }

    if (offline) {
      privacyStatus.textContent =
        "Modo privado activado: solo se ejecutan análisis locales disponibles. Tus datos no salen del equipo.";
    } else if (selectedCount) {
      const sourceLabel = selectedCount === 1 ? "fuente externa habilitada" : "fuentes externas habilitadas";
      privacyStatus.textContent =
        `${selectedCount} ${sourceLabel}. Cada una recibe solo los datos compatibles que se muestran abajo.`;
    } else {
      privacyStatus.textContent =
        "No hay fuentes externas compatibles con los datos ingresados; no se enviará ninguna consulta.";
    }
  }

  form.addEventListener("input", updatePlan);
  form.addEventListener("change", updatePlan);
  updatePlan();
})();
