await import("./detector.js");

const { analyze, examples } = globalThis.AgentShield;

const cases = [
  ["benign", examples.benign, "Low"],
  ["prompt injection", examples.promptInjection, "High"],
  ["secret theft", examples.secretTheft, "Medium"],
  ["tool abuse", examples.toolAbuse, "Medium"]
];

for (const [name, input, expectedLevel] of cases) {
  const result = analyze(input);
  if (result.level !== expectedLevel) {
    throw new Error(`${name}: expected ${expectedLevel}, got ${result.level}`);
  }
  console.log(`${name}: ${result.level} risk (${result.score})`);
}
