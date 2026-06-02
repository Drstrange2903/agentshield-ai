const { analyze, examples } = globalThis.AgentShield;

const input = document.querySelector("#promptInput");
const scenarioSelect = document.querySelector("#scenarioSelect");
const scanButton = document.querySelector("#scanButton");
const clearButton = document.querySelector("#clearButton");
const azureToggle = document.querySelector("#azureToggle");
const scoreCard = document.querySelector("#scoreCard");
const riskScore = document.querySelector("#riskScore");
const riskLevel = document.querySelector("#riskLevel");
const decisionText = document.querySelector("#decisionText");
const findingList = document.querySelector("#findingList");

async function analyzeWithAzure(content) {
  if (!azureToggle.checked || window.location.protocol === "file:") {
    return analyze(content);
  }

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content })
    });

    if (!response.ok) {
      throw new Error(`Azure scan failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    const fallback = analyze(content);
    fallback.matches.unshift({
      title: "Azure Scan Unavailable",
      tag: "Fallback",
      explanation: error.message,
      action: "Used local explainable firewall rules instead."
    });
    return fallback;
  }
}

function render(result) {
  riskScore.textContent = result.score;
  riskLevel.textContent = `${result.level} risk`;
  decisionText.textContent = result.decision;
  scoreCard.className = `score-card ${result.className}`;

  findingList.innerHTML = "";
  result.matches.forEach((match) => {
    const item = document.createElement("article");
    item.className = "finding";
    item.innerHTML = `
      <strong>${match.title}<span class="tag">${match.tag}</span></strong>
      <p>${match.explanation}</p>
      <p><b>Recommended action:</b> ${match.action}</p>
    `;
    findingList.appendChild(item);
  });
}

scenarioSelect.addEventListener("change", async () => {
  if (!scenarioSelect.value) return;
  input.value = examples[scenarioSelect.value];
  render(await analyzeWithAzure(input.value));
});

scanButton.addEventListener("click", async () => {
  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  render(await analyzeWithAzure(input.value));
  scanButton.disabled = false;
  scanButton.textContent = "Scan Content";
});

clearButton.addEventListener("click", () => {
  input.value = "";
  scenarioSelect.value = "";
  riskScore.textContent = "0";
  riskLevel.textContent = "Waiting for scan";
  decisionText.textContent = "No content scanned yet.";
  scoreCard.className = "score-card";
  findingList.innerHTML = '<article class="empty-state">Scan content to see detected risks, recommended actions, and safe handling guidance.</article>';
});
