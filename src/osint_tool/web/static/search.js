(() => {
  "use strict";

  const form = document.querySelector('form[action="/"]');
  const fields = [...form.querySelectorAll(".field input")];
  const modules = [...document.querySelectorAll(".analysis-item")];
  const labels = new Map(fields.map((field) => [field.id, field.labels[0]?.textContent.trim()]));

  form.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-focus-field]");
    if (trigger) {
      document.getElementById(trigger.dataset.focusField)?.focus();
    }
  });

  function updatePlan() {
    const provided = new Set(
      fields.filter((field) => field.value.trim()).map((field) => field.id),
    );

    for (const item of modules) {
      const accepts = item.dataset.accepts.split(" ");
      const applicable = accepts.some((field) => provided.has(field));
      const optional = item.dataset.optional === "true";
      const toggle = item.querySelector('input[type="checkbox"]');
      const active = applicable && (!optional || toggle.checked);
      const state = item.querySelector(".analysis-state");

      item.dataset.active = String(active);
      if (!applicable) {
        const requirements = accepts.map((field) => labels.get(field)).filter(Boolean);
        const requirement = requirements.length > 1 ? requirements.join(" o ") : requirements[0];
        state.textContent = `${optional && toggle.checked ? "Activado · requiere" : "Requiere"} ${requirement}`;
      } else if (optional && !toggle.checked) {
        state.textContent = "Opcional; activar para incluir";
      } else {
        state.textContent = "Se ejecutará";
      }
    }
  }

  form.addEventListener("input", updatePlan);
  form.addEventListener("change", updatePlan);
  updatePlan();
})();
