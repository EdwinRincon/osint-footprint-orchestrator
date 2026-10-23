(() => {
  "use strict";

  const form = document.querySelector('form[action="/"]');
  const fields = [...form.querySelectorAll(".field input")];
  const modules = [...document.querySelectorAll(".analysis-item")];

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
        state.textContent = optional && toggle.checked
          ? "Activado; falta una entrada compatible"
          : "No aplica a las entradas actuales";
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
