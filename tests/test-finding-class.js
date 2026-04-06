#!/usr/bin/env node
"use strict";
/**
 * Test Suite for Finding Class
 * Tests construction, score calculation, and MITRE ATT&CK mapping
 */

const { Finding, MITRE_ATTACK } = require("../scan");

const colors = {
  green: "\x1b[32m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  reset: "\x1b[0m",
};

let passed = 0;
let failed = 0;

function assertEquals(actual, expected, testName) {
  const actualStr = JSON.stringify(actual);
  const expectedStr = JSON.stringify(expected);

  if (actualStr === expectedStr) {
    console.log(`${colors.green}✓${colors.reset} ${testName}`);
    passed++;
  } else {
    console.log(`${colors.red}✗${colors.reset} ${testName}`);
    console.log(`  Expected: ${expectedStr}`);
    console.log(`  Actual:   ${actualStr}`);
    failed++;
  }
}

function assert(condition, testName) {
  if (condition) {
    console.log(`${colors.green}✓${colors.reset} ${testName}`);
    passed++;
  } else {
    console.log(`${colors.red}✗${colors.reset} ${testName}`);
    failed++;
  }
}

function test(name, fn) {
  console.log(`\n${colors.cyan}${name}${colors.reset}`);
  fn();
}

test("Finding maps MITRE technique to tactic and name", () => {
  const f = new Finding("T1195", "desc", "HIGH", "ev", "file");
  assertEquals(f.technique, "T1195", "technique stored");
  assertEquals(f.tactic, "Initial Access", "tactic from MITRE_ATTACK map");
  assertEquals(f.name, "Supply Chain Compromise", "name from MITRE_ATTACK map");
});

test("Finding with unknown technique defaults to Unknown", () => {
  const f = new Finding("T9999", "desc", "HIGH", "ev", "file");
  assertEquals(f.tactic, "Unknown", "unknown technique → Unknown tactic");
  assertEquals(f.name, "Unknown", "unknown technique → Unknown name");
});

test("CRITICAL severity multiplier is 4x", () => {
  const f = new Finding("T1195", "desc", "CRITICAL", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 4, "CRITICAL = baseScore × 4");
});

test("HIGH severity multiplier is 2x", () => {
  const f = new Finding("T1195", "desc", "HIGH", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 2, "HIGH = baseScore × 2");
});

test("MEDIUM severity multiplier is 1x", () => {
  const f = new Finding("T1195", "desc", "MEDIUM", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 1, "MEDIUM = baseScore × 1");
});

test("LOW severity multiplier is 0.5x", () => {
  const f = new Finding("T1195", "desc", "LOW", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 0.5, "LOW = baseScore × 0.5");
});

test("WARNING severity multiplier is 0.05x", () => {
  const f = new Finding("T1195", "desc", "WARNING", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 0.05, "WARNING = baseScore × 0.05");
});

test("Unknown severity defaults to 1x multiplier", () => {
  const f = new Finding("T1195", "desc", "UNKNOWN_SEV", "ev", "file");
  const baseScore = MITRE_ATTACK["T1195"].baseScore;
  assertEquals(f.score, baseScore * 1, "unknown severity = baseScore × 1");
});

test("Unknown technique defaults to baseScore 1", () => {
  const f = new Finding("T9999", "desc", "CRITICAL", "ev", "file");
  assertEquals(f.score, 1 * 4, "unknown technique baseScore=1, CRITICAL=4x");
});

test("All MITRE techniques have proper tactic and name", () => {
  const techniques = Object.keys(MITRE_ATTACK);
  assert(techniques.length > 0, "MITRE_ATTACK has entries");

  for (const t of techniques) {
    const entry = MITRE_ATTACK[t];
    assert(typeof entry.name === "string" && entry.name.length > 0, `${t} has a name`);
    assert(typeof entry.tactic === "string" && entry.tactic.length > 0, `${t} has a tactic`);
    assert(typeof entry.baseScore === "number" && entry.baseScore > 0, `${t} has positive baseScore`);
  }
});

test("Finding stores all constructor fields", () => {
  const f = new Finding("T1064", "My Desc", "MEDIUM", "My Evidence", "scan.js");
  assertEquals(f.technique, "T1064", "technique");
  assertEquals(f.description, "My Desc", "description");
  assertEquals(f.severity, "MEDIUM", "severity");
  assertEquals(f.evidence, "My Evidence", "evidence");
  assertEquals(f.file, "scan.js", "file");
});

test("Score ordering across severity levels for same technique", () => {
  const critical = new Finding("T1059", "d", "CRITICAL", "e", "f");
  const high = new Finding("T1059", "d", "HIGH", "e", "f");
  const medium = new Finding("T1059", "d", "MEDIUM", "e", "f");
  const low = new Finding("T1059", "d", "LOW", "e", "f");
  const warning = new Finding("T1059", "d", "WARNING", "e", "f");

  assert(critical.score > high.score, "CRITICAL > HIGH");
  assert(high.score > medium.score, "HIGH > MEDIUM");
  assert(medium.score > low.score, "MEDIUM > LOW");
  assert(low.score > warning.score, "LOW > WARNING");
});

// Summary
console.log(`\n${colors.cyan}Test Results:${colors.reset}`);
console.log(`${colors.green}Passed: ${passed}${colors.reset}`);
if (failed > 0) {
  console.log(`${colors.red}Failed: ${failed}${colors.reset}`);
  process.exit(1);
} else {
  console.log(`${colors.green}All tests passed!${colors.reset}`);
  process.exit(0);
}
