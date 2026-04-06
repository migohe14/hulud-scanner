#!/usr/bin/env node
"use strict";
/**
 * Test Suite for calculateRisk Function
 * Tests risk scoring, verdict calculation, and family prediction
 */

const { calculateRisk, Finding } = require("../scan");

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

console.log(
  `${colors.cyan}Running Risk Calculation Tests...${colors.reset}\n`,
);

// Test 1: Empty findings → LOW verdict
const test1 = calculateRisk([]);
assertEquals(test1.verdict, "LOW", "Empty findings produce LOW verdict");
assertEquals(test1.totalScore, 0, "Empty findings produce zero score");
assertEquals(test1.suspectedFamily, "None", "Empty findings produce no family");

// Test 2: Single LOW finding does not affect score
const test2 = calculateRisk([
  new Finding("T1064", "test", "LOW", "evidence", "file.js"),
]);
assertEquals(test2.verdict, "LOW", "Single LOW finding stays LOW");
assertEquals(test2.totalScore, 0, "LOW findings are excluded from scoring");

// Test 3: Single WARNING finding does not affect score
const test3 = calculateRisk([
  new Finding("T1064", "test", "WARNING", "evidence", "file.js"),
]);
assertEquals(test3.verdict, "LOW", "Single WARNING finding stays LOW");
assertEquals(test3.totalScore, 0, "WARNING findings are excluded from scoring");

// Test 4: CRITICAL supply chain finding produces high score
const test4 = calculateRisk([
  new Finding("T1195", "Compromised Package", "CRITICAL", "evidence", "pkg"),
]);
assert(test4.totalScore > 0, "CRITICAL T1195 produces positive score");
assert(
  test4.techniques.includes("T1195"),
  "T1195 technique detected",
);

// Test 5: Shai-Hulud correlation (T1064 + T1552 + T1518)
const test5 = calculateRisk([
  new Finding("T1064", "Lifecycle Hook", "MEDIUM", "preinstall", "pkg.json"),
  new Finding("T1552", "Env Access", "MEDIUM", "process.env", "file.js"),
  new Finding("T1518", "CI Discovery", "MEDIUM", "GITHUB_ACTIONS", "file.js"),
]);
assertEquals(
  test5.suspectedFamily,
  "Shai-Hulud (High Confidence)",
  "T1064+T1552+T1518 correlation triggers Shai-Hulud family",
);
assert(
  test5.totalScore >= 50,
  "Correlation bonus adds at least 50 to score",
);

// Test 6: Generic Malware Loader correlation (T1064 + T1059)
const test6 = calculateRisk([
  new Finding("T1064", "Lifecycle Hook", "MEDIUM", "preinstall", "pkg.json"),
  new Finding("T1059", "Process Exec", "MEDIUM", "child_process", "file.js"),
]);
assertEquals(
  test6.suspectedFamily,
  "Generic Malware Loader",
  "T1064+T1059 triggers Generic Malware Loader family",
);

// Test 7: Shai-Hulud indicator in description triggers family
const test7 = calculateRisk([
  new Finding("T1195", "Shai-Hulud Loader", "CRITICAL", "setup_bun.js", "file"),
]);
assertEquals(
  test7.suspectedFamily,
  "Shai-Hulud (High Confidence)",
  "Shai-Hulud keyword in description triggers family",
);

// Test 8: Trufflehog indicator in evidence triggers family
const test8 = calculateRisk([
  new Finding("T1552", "Artifact Found", "HIGH", "trufflehog cache", "home"),
]);
assertEquals(
  test8.suspectedFamily,
  "Shai-Hulud (High Confidence)",
  "Trufflehog keyword in evidence triggers family",
);

// Test 9: Safety cap — no CRITICAL verdict without CRITICAL findings
const test9Findings = [];
for (let i = 0; i < 20; i++) {
  test9Findings.push(
    new Finding("T1064", "Hook", "MEDIUM", "script", "file.js"),
  );
}
const test9 = calculateRisk(test9Findings);
assert(
  test9.verdict !== "CRITICAL",
  "Safety cap prevents CRITICAL without CRITICAL findings",
);

// Test 10: Multiple CRITICAL findings can produce CRITICAL verdict
const test10 = calculateRisk([
  new Finding("T1195", "Compromised Package", "CRITICAL", "pkg@1.0.0", "nm"),
  new Finding("T1195", "Malicious Hash", "CRITICAL", "hash:abc", "file.js"),
  new Finding("T1059", "Process Exec", "CRITICAL", "child_process", "file.js"),
]);
assertEquals(
  test10.verdict,
  "CRITICAL",
  "Multiple CRITICAL findings produce CRITICAL verdict",
);

// Test 11: Finding score multipliers
const criticalFinding = new Finding("T1195", "test", "CRITICAL", "ev", "f");
const highFinding = new Finding("T1195", "test", "HIGH", "ev", "f");
const mediumFinding = new Finding("T1195", "test", "MEDIUM", "ev", "f");
const lowFinding = new Finding("T1195", "test", "LOW", "ev", "f");

assert(
  criticalFinding.score > highFinding.score,
  "CRITICAL score > HIGH score",
);
assert(
  highFinding.score > mediumFinding.score,
  "HIGH score > MEDIUM score",
);
assert(
  mediumFinding.score > lowFinding.score,
  "MEDIUM score > LOW score",
);

// Test 12: Finding constructor populates fields
const finding12 = new Finding(
  "T1195",
  "Test Description",
  "HIGH",
  "Test Evidence",
  "test-file.js",
);
assertEquals(finding12.technique, "T1195", "Finding technique set");
assertEquals(finding12.tactic, "Initial Access", "Finding tactic from MITRE");
assertEquals(finding12.name, "Supply Chain Compromise", "Finding name from MITRE");
assertEquals(finding12.description, "Test Description", "Finding description set");
assertEquals(finding12.severity, "HIGH", "Finding severity set");
assertEquals(finding12.evidence, "Test Evidence", "Finding evidence set");
assertEquals(finding12.file, "test-file.js", "Finding file set");

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
