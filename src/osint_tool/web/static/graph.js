(() => {
  "use strict";

  const container = document.querySelector("#network");
  const details = document.querySelector("#details");
  const elements = JSON.parse(container.dataset.elements);
  const nodes = elements.filter((element) => !element.data.source);
  if (nodes.length === 0) return;

  container.replaceChildren();
  const graph = cytoscape({
    container,
    elements,
    minZoom: 0.15,
    maxZoom: 3,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#8cb8d8",
          "border-color": "#416d8c",
          "border-width": 1.5,
          color: "#172b2a",
          label: "data(label)",
          "font-size": 10,
          "text-wrap": "wrap",
          "text-max-width": 130,
          "text-valign": "center",
          "text-halign": "center",
          width: 180,
          height: 72,
          padding: 8,
          shape: "round-rectangle",
        },
      },
      {
        selector: "node.target",
        style: {
          "background-color": "#17695e",
          "border-color": "#0f4c44",
          color: "#ffffff",
          "font-weight": "bold",
          shape: "round-rectangle",
        },
      },
      {
        selector: "edge",
        style: {
          width: "mapData(confidence, 0, 1, 1, 3)",
          "line-color": "#63867e",
          "target-arrow-color": "#63867e",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "",
          color: "#42534f",
          "font-size": 8,
          "text-background-color": "#fbfdfc",
          "text-background-opacity": 0.9,
          "text-background-padding": 2,
        },
      },
      {
        selector: "edge[confidence < 0.7]",
        style: { "line-style": "dashed", "line-color": "#87928f" },
      },
      { selector: ":selected", style: { "border-width": 4, "border-color": "#d97835" } },
    ],
  });
  let layout = graph.layout({
    name: "cose",
    animate: "end",
    animationDuration: 500,
    fit: true,
    padding: 40,
  });
  let layoutActive = true;
  layout.run();

  graph.on("tap", "node", (event) => {
    const node = event.target.data();
    details.textContent = `${node.kind}: ${node.value}${node.is_target ? " (dato de entrada)" : ""}`;
  });
  graph.on("tap", "edge", (event) => {
    const edge = event.target.data();
    const evidence = edge.evidence.length ? edge.evidence.join(", ") : "origen no especificado";
    details.textContent =
      `${edge.label}. Evidencia: ${evidence}. Confianza heurística: ` +
      `${Math.round(edge.confidence * 100)}%. Esto no demuestra identidad común.`;
  });
  document.querySelector("#fit").addEventListener("click", () => graph.fit(undefined, 40));
  const toggleLayoutButton = document.querySelector("#toggle-layout");
  graph.on("layoutstop", () => {
    layoutActive = false;
    toggleLayoutButton.textContent = "Reanudar distribución";
  });
  toggleLayoutButton.addEventListener("click", () => {
    if (layoutActive) {
      layout.stop();
      layoutActive = false;
      toggleLayoutButton.textContent = "Reanudar distribución";
    } else {
      layout = graph.layout({
        name: "cose",
        animate: "end",
        animationDuration: 500,
        fit: true,
        padding: 40,
      });
      layoutActive = true;
      toggleLayoutButton.textContent = "Detener distribución";
      layout.run();
    }
  });
  document.querySelector("#export").addEventListener("click", () => {
    const link = document.createElement("a");
    link.href = graph.png({ full: true, scale: 2, bg: "#fbfdfc" });
    link.download = "grafo-osint.png";
    link.click();
  });
})();
