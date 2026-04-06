#!/usr/bin/env node
"use strict";
/**
 * Test Suite for parseCompromisedLibs Function
 * Tests parsing of IOC lines in various formats
 */

const { parseCompromisedLibs } = require("../scan");

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

console.log(
  `${colors.cyan}Running Compromised Libs Parser Tests...${colors.reset}\n`,
);

// Test 1: Colon-separated format (name:version)
const test1 = parseCompromisedLibs(["evil-pkg:1.0.0"]);
assertEquals(test1, ["evil-pkg@1.0.0"], "Colon-separated format");

// Test 2: Comma-equals format with single version (name,= version)
const test2 = parseCompromisedLibs(["test-pkg,= 1.0.0"]);
assertEquals(test2, ["test-pkg@1.0.0"], "Comma-equals format single version");

// Test 3: Comma-equals format with multiple versions (name,= v1 || = v2)
const test3 = parseCompromisedLibs([
  "test-foundry-app,= 1.0.4 || = 1.0.3 || = 1.0.2",
]);
assertEquals(
  test3,
  [
    "test-foundry-app@1.0.4",
    "test-foundry-app@1.0.3",
    "test-foundry-app@1.0.2",
  ],
  "Comma-equals format multiple versions with ||",
);

// Test 4: At-sign format (name@version)
const test4 = parseCompromisedLibs(["minimist@1.2.5"]);
assertEquals(test4, ["minimist@1.2.5"], "At-sign format");

// Test 5: Scoped package with @ format (@scope/pkg@version)
const test5 = parseCompromisedLibs(["@scope/evil-pkg@2.0.1"]);
assertEquals(test5, ["@scope/evil-pkg@2.0.1"], "Scoped package @ format");

// Test 6: Multiple lines of different formats
const test6 = parseCompromisedLibs([
  "pkg-a:1.0.0",
  "pkg-b,= 2.0.0",
  "pkg-c@3.0.0",
]);
assertEquals(
  test6,
  ["pkg-a@1.0.0", "pkg-b@2.0.0", "pkg-c@3.0.0"],
  "Mixed formats",
);

// Test 7: Empty input
const test7 = parseCompromisedLibs([]);
assertEquals(test7, [], "Empty input returns empty array");

// Test 8: Comma-equals with spaces in versions
const test8 = parseCompromisedLibs(["my-pkg,= 1.0.0 || = 1.0.1"]);
assertEquals(
  test8,
  ["my-pkg@1.0.0", "my-pkg@1.0.1"],
  "Comma-equals with spaces trimmed",
);

// Test 9: Scoped package without version separator is not added
const test9 = parseCompromisedLibs(["@scope/pkg"]);
assertEquals(test9, [], "Scoped package without version is ignored");

// Test 10: Line with only a package name (no version separator) is ignored
const test10 = parseCompromisedLibs(["just-a-name"]);
assertEquals(test10, [], "Plain name without version separator is ignored");

// Test 11: Multiple entries for same package different versions
const test11 = parseCompromisedLibs([
  "evil-pkg:1.0.0",
  "evil-pkg:2.0.0",
  "evil-pkg:3.0.0",
]);
assertEquals(
  test11,
  ["evil-pkg@1.0.0", "evil-pkg@2.0.0", "evil-pkg@3.0.0"],
  "Multiple versions of same package",
);

// Test 12: Real-world mixed format
const test12 = parseCompromisedLibs([
  "@alexadark/gatsby-theme-wordpress-blog,= 2.0.1",
  "test-foundry-app,= 1.0.4 || = 1.0.3",
  "minimist@1.2.5",
  "evil-lib:0.9.0",
]);
assertEquals(
  test12,
  [
    "@alexadark/gatsby-theme-wordpress-blog@2.0.1",
    "test-foundry-app@1.0.4",
    "test-foundry-app@1.0.3",
    "minimist@1.2.5",
    "evil-lib@0.9.0",
  ],
  "Real-world mixed format input",
);

// Test 13: Axios supply chain attack entries (colon format)
const test13 = parseCompromisedLibs([
  "axios:1.14.1",
  "axios:0.30.4",
  "plain-crypto-js:4.2.1",
]);
assertEquals(
  test13,
  [
    "axios@1.14.1",
    "axios@0.30.4",
    "plain-crypto-js@4.2.1",
  ],
  "Axios supply chain attack versions parsed correctly",
);

// Test 14: Axios-related typosquatting packages
const test14 = parseCompromisedLibs([
  "axios-builder:1.2.1",
  "axios-cancelable:1.0.2",
  "axios-cancelable:1.0.1",
  "axios-timed:1.0.2",
  "axios-timed:1.0.1",
]);
assertEquals(
  test14,
  [
    "axios-builder@1.2.1",
    "axios-cancelable@1.0.2",
    "axios-cancelable@1.0.1",
    "axios-timed@1.0.2",
    "axios-timed@1.0.1",
  ],
  "Axios typosquatting packages parsed correctly",
);

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
