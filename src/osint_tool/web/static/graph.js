(() => {
  "use strict";

  const container = document.querySelector("#network");
  const details = document.querySelector("#details");
  const summary = document.querySelector("#graph-summary");
  const layoutButton = document.querySelector("#layout");
  const resetGroupsButton = document.querySelector("#reset-groups");
  const exportButton = document.querySelector("#export");
  const exportStatus = document.querySelector("#export-status");
  const graphData = JSON.parse(document.querySelector("#graph-data").textContent);
  const { elements, groups } = graphData;
  if (graphData.node_count === 0) {
    exportButton.disabled = true;
    layoutButton.disabled = true;
    exportStatus.textContent = "No hay relaciones para exportar.";
    summary.textContent = "No hay relaciones para visualizar.";
    return;
  }

  container.replaceChildren();
  const graph = cytoscape({
    container,
    elements: [],
    minZoom: 0.03,
    maxZoom: 3,
    hideEdgesOnViewport: true,
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
          "curve-style": "straight",
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
      {
        selector: "node.aggregate",
        style: {
          "background-color": "#f4e7bd",
          "border-color": "#a07824",
          "font-weight": "bold",
        },
      },
      { selector: ":selected", style: { "border-width": 4, "border-color": "#d97835" } },
    ],
  });
  graph.add(elements);
  const initialGroupCount = Object.keys(groups).length;
  let collapsedGroupCount = initialGroupCount;

  function runLayout() {
    graph.layout({
      name: "breadthfirst",
      directed: true,
      avoidOverlap: true,
      spacingFactor: 1.1,
      animate: false,
      fit: true,
      padding: 40,
    }).run();
  }

  function updateSummary() {
    const number = new Intl.NumberFormat("es");
    const groupSummary = collapsedGroupCount === 1
      ? "1 grupo resumido; selecciona el grupo para desplegarlo."
      : `${number.format(collapsedGroupCount)} grupos resumidos; selecciona uno para desplegarlo.`;
    summary.textContent =
      `${number.format(graphData.node_count)} entidades · ` +
      `${number.format(graphData.relation_count)} relaciones` +
      (collapsedGroupCount
        ? `. ${groupSummary}`
        : ".");
  }

  function expandGroup(groupId) {
    const members = groups[groupId];
    if (!members) return;
    collapsedGroupCount -= 1;
    graph.batch(() => {
      for (const member of members) {
        const nodeId = member.node.data.id;
        if (graph.getElementById(nodeId).empty()) graph.add(member.node);
        if (graph.getElementById(member.edge.data.id).empty()) graph.add(member.edge);
      }
      graph.getElementById(groupId).remove();
    });
    resetGroupsButton.hidden = false;
    updateSummary();
    runLayout();
  }

  graph.on("tap", "node", (event) => {
    const node = event.target.data();
    if (node.is_group) {
      details.textContent =
        `${node.value}. Confianza heurística media: ` +
        `${Math.round(node.confidence * 100)}%. Desplegando relaciones…`;
      expandGroup(node.id);
      return;
    }
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
  layoutButton.addEventListener("click", runLayout);
  resetGroupsButton.addEventListener("click", () => {
    graph.elements().remove();
    graph.add(elements);
    collapsedGroupCount = initialGroupCount;
    resetGroupsButton.hidden = true;
    updateSummary();
    runLayout();
  });
  updateSummary();
  runLayout();

  exportButton.addEventListener("click", () => {
    exportStatus.textContent = "Generando imagen PNG…";
    try {
      const image = graph.png({ full: true, scale: 2, bg: "#fbfdfc" });
      const [metadata, encodedImage] = image.split(",", 2);
      if (metadata !== "data:image/png;base64" || !encodedImage) {
        throw new Error("Cytoscape no devolvió una imagen PNG válida.");
      }
      const bytes = Uint8Array.from(atob(encodedImage), (character) =>
        character.charCodeAt(0),
      );
      const downloadUrl = URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = "grafo-osint.png";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 60_000);
      exportStatus.textContent = "Descarga de la imagen PNG iniciada.";
    } catch (error) {
      console.error("No se pudo exportar el grafo como PNG.", error);
      exportStatus.textContent = "No se pudo generar la imagen PNG. Inténtalo de nuevo.";
    }
  });
})();
