import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  FileCode2,
  Plus,
  Trash2,
  Download,
  History as HistoryIcon,
  ArrowLeft,
  Loader2,
  AlertTriangle,
  AlertOctagon,
  Info,
  X,
} from "lucide-react";

/* =========================================================================
   ANALYSIS ENGINE
   Pure pattern/heuristic based static analysis. Runs entirely in the
   browser — no network calls, nothing leaves the page. This is a first
   pass, not a replacement for a manual audit or a real compiler/EVM
   simulation (which this environment cannot run).
   ========================================================================= */

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const SEVERITY_META = {
  critical: { label: "Critical", color: "#ff4d6d", weight: 20 },
  high: { label: "High", color: "#ff8f6d", weight: 10 },
  medium: { label: "Medium", color: "#f5c451", weight: 5 },
  low: { label: "Low", color: "#3addff", weight: 2 },
  info: { label: "Info", color: "#8b93a7", weight: 0.5 },
};

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function lineOf(code, index) {
  if (index < 0) return 1;
  return code.slice(0, index).split("\n").length;
}

function forEachMatch(code, regex, cb) {
  const flags = regex.flags.includes("g") ? regex.flags : regex.flags + "g";
  const re = new RegExp(regex.source, flags);
  let m;
  while ((m = re.exec(code))) {
    cb(m.index, m);
    if (m.index === re.lastIndex) re.lastIndex++;
  }
}

function splitFunctions(code) {
  const results = [];
  const fnRegex = /function\s+([a-zA-Z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = fnRegex.exec(code))) {
    const start = m.index;
    const name = m[1];
    const braceStart = code.indexOf("{", fnRegex.lastIndex);
    if (braceStart === -1) continue;
    const header = code.slice(start, braceStart);
    let depth = 0;
    let i = braceStart;
    for (; i < code.length; i++) {
      if (code[i] === "{") depth++;
      else if (code[i] === "}") {
        depth--;
        if (depth === 0) {
          i++;
          break;
        }
      }
    }
    const body = code.slice(braceStart, i);
    results.push({ name, header, body, start });
    fnRegex.lastIndex = i;
  }
  return results;
}

function parseContractContext(code) {
  const stateVars = new Set();
  const modifiers = new Set();

  // Strip function/modifier/constructor bodies so what's left is
  // (mostly) contract-level declarations — a cheap way to avoid
  // treating local variables as state variables.
  const fnLike =
    /(function\s+[a-zA-Z_$][\w$]*\s*\([^)]*\)[^{;]*|modifier\s+[a-zA-Z_$][\w$]*\s*\([^)]*\)[^{;]*|constructor\s*\([^)]*\)[^{;]*)\{/g;
  let m;
  let cursor = 0;
  let topLevel = "";
  while ((m = fnLike.exec(code))) {
    topLevel += code.slice(cursor, m.index);
    const braceStart = fnLike.lastIndex - 1;
    let depth = 0;
    let i = braceStart;
    for (; i < code.length; i++) {
      if (code[i] === "{") depth++;
      else if (code[i] === "}") {
        depth--;
        if (depth === 0) {
          i++;
          break;
        }
      }
    }
    cursor = i;
    fnLike.lastIndex = i;
  }
  topLevel += code.slice(cursor);

  forEachMatch(
    topLevel,
    /\b(uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|address|bool|string|bytes(?:32)?|mapping\s*\([^)]*\))\s*(?:public|private|internal|external)?\s*(?:constant|immutable)?\s*([a-zA-Z_$][\w$]*)\s*[;=]/g,
    (idx, mm) => stateVars.add(mm[2])
  );

  forEachMatch(code, /modifier\s+([a-zA-Z_$][\w$]*)\s*\(/g, (idx, mm) => modifiers.add(mm[1]));

  return { stateVars, modifiers };
}

function analyzeSolidity(code, fileName) {
  const findings = [];
  const ctx = parseContractContext(code);
  const add = (severity, title, idxOrLine, message, recommendation, isLine) => {
    findings.push({
      file: fileName,
      severity,
      title,
      line: isLine ? idxOrLine : lineOf(code, idxOrLine),
      message,
      recommendation,
    });
  };

  if (!/SPDX-License-Identifier/.test(code)) {
    add(
      "low",
      "Missing SPDX license identifier",
      1,
      "No SPDX-License-Identifier comment was found in this file.",
      "Add // SPDX-License-Identifier: MIT (or the applicable license) as the first line.",
      true
    );
  }

  const pragmaMatch = code.match(/pragma solidity\s*([^;]+);/);
  if (pragmaMatch) {
    const pragmaLine = lineOf(code, pragmaMatch.index);
    const versionExpr = pragmaMatch[1].trim();
    if (/[\^><]/.test(versionExpr)) {
      add(
        "low",
        "Floating pragma",
        pragmaLine,
        `The pragma allows a range of compiler versions (${versionExpr}) instead of one exact version.`,
        "Lock the pragma to the single compiler version the contract was actually tested and audited with.",
        true
      );
    }
    const verNum = versionExpr.match(/(\d+)\.(\d+)/);
    if (verNum) {
      const major = Number(verNum[1]);
      const minor = Number(verNum[2]);
      if (major === 0 && minor < 8) {
        const hasSafeMath = /SafeMath/.test(code);
        add(
          hasSafeMath ? "low" : "high",
          "Pre-0.8 compiler without built-in overflow checks",
          pragmaLine,
          `The compiler target (${versionExpr}) predates Solidity 0.8's automatic arithmetic overflow and underflow checks.${
            hasSafeMath
              ? " SafeMath usage was detected, which mitigates this for the calls it wraps."
              : " No SafeMath usage was detected in this file."
          }`,
          "Upgrade to Solidity ^0.8.0 or later, or apply SafeMath consistently to every arithmetic operation on user-influenced values.",
          true
        );
      }
    }
  } else {
    add(
      "medium",
      "No pragma statement found",
      1,
      "This file has no pragma solidity statement.",
      "Add an explicit pragma solidity version so the intended compiler is unambiguous.",
      true
    );
  }

  forEachMatch(code, /tx\.origin/g, (idx) =>
    add(
      "high",
      "Use of tx.origin for authorization",
      idx,
      "tx.origin was found in this contract. Authorization based on tx.origin can be bypassed if a user is tricked into interacting through a malicious intermediary contract.",
      "Use msg.sender for authorization checks instead of tx.origin."
    )
  );

  forEachMatch(code, /\.delegatecall\(/g, (idx) =>
    add(
      "high",
      "Use of delegatecall",
      idx,
      "delegatecall executes external code in the caller's own storage context. If the target is untrusted, or a proxy's storage layout drifts from its implementation, this can corrupt contract state.",
      "Only delegatecall to a trusted, storage-layout-compatible target, and keep proxy/implementation storage layouts in lockstep."
    )
  );

  forEachMatch(code, /selfdestruct\(|suicide\(/g, (idx) =>
    add(
      "high",
      "Use of selfdestruct",
      idx,
      "selfdestruct permanently removes the contract's code and force-sends its remaining balance. It is a frequent target of access-control mistakes.",
      "Gate selfdestruct behind strong access control, or avoid it in favor of a pausable/upgradeable pattern."
    )
  );

  forEachMatch(code, /block\.timestamp|(^|[^.\w])now\b/g, (idx) =>
    add(
      "medium",
      "block.timestamp / now usage",
      idx,
      "block.timestamp (and the deprecated now) can be nudged within a small window by whoever produces the block.",
      "Avoid using block.timestamp for randomness or strict equality checks; it's fine for coarse, tolerant time windows only."
    )
  );

  forEachMatch(code, /blockhash\(/g, (idx) =>
    add(
      "high",
      "blockhash used as a randomness source",
      idx,
      "blockhash is predictable ahead of time by anyone simulating the next block, and is unusable as a randomness source once older than 256 blocks.",
      "Use a verifiable randomness solution (for example Chainlink VRF) instead of blockhash."
    )
  );

  forEachMatch(code, /assembly\s*\{/g, (idx) =>
    add(
      "medium",
      "Inline assembly block",
      idx,
      "Inline assembly bypasses Solidity's normal safety checks and is easy to get subtly wrong.",
      "Have this block reviewed manually — pattern scanning can't verify assembly correctness."
    )
  );

  forEachMatch(code, /\.call\{[^}]*\}\(|\.call\(/g, (idx) => {
    const before = code.slice(Math.max(0, idx - 120), idx);
    const after = code.slice(idx, idx + 160);
    const looksChecked =
      /require\s*\($/.test(before.trim()) ||
      /\(\s*bool\s+\w+[^=(){}]*\)\s*=\s*[\w.]+$/.test(before) ||
      /success/i.test(before) ||
      /success/i.test(after.slice(0, 80));
    if (!looksChecked) {
      add(
        "high",
        "Possibly unchecked low-level call",
        idx,
        "A .call( was found where the boolean success value doesn't appear to be captured or checked nearby.",
        'Capture and check the return value: (bool ok, ) = target.call(...); require(ok, "call failed");'
      );
    }
  });

  forEachMatch(code, /\.send\(|\.transfer\(/g, (idx) =>
    add(
      "low",
      ".send/.transfer used for an ETH transfer",
      idx,
      ".send and .transfer forward a fixed 2300 gas stipend, which breaks against recipients with non-trivial receive/fallback logic (including some multisig and smart-contract wallets).",
      'Prefer .call{value: amount}("") paired with an explicit success check, following checks-effects-interactions.'
    )
  );

  const knownModifiers = Array.from(ctx.modifiers);
  const functions = splitFunctions(code);

  functions.forEach((fn) => {
    const hasCustomGuard = knownModifiers.some((mod) => new RegExp(`\\b${mod}\\b`).test(fn.header));
    const hasReentrancyGuard =
      /nonReentrant/i.test(fn.header) ||
      knownModifiers.some((mod) => /reentr/i.test(mod) && new RegExp(`\\b${mod}\\b`).test(fn.header));

    // Reentrancy: only fires when the assignment target after the external
    // call is a real, contract-level state variable — not just any identifier.
    const callIdx = fn.body.search(/\.call\{[^}]*\}\(|\.call\(|\.send\(|\.transfer\(/);
    if (callIdx !== -1 && !hasReentrancyGuard) {
      const after = fn.body.slice(callIdx);
      const assignRe = /\n\s*([a-zA-Z_][\w.\[\]]*)\s*(\+=|-=|=)(?!=)/g;
      let am;
      while ((am = assignRe.exec(after))) {
        const target = am[1].split(/[.[]/)[0];
        if (ctx.stateVars.has(target)) {
          add(
            "critical",
            "Possible reentrancy (state change after external call)",
            fn.start + callIdx,
            `Function "${fn.name}" makes an external call and then updates state variable "${target}" afterward, without an obvious reentrancy guard.`,
            "Update state before making external calls (checks-effects-interactions), and/or apply a reentrancy guard such as OpenZeppelin's ReentrancyGuard."
          );
          break;
        }
      }
    }

    const isExternalOrPublic = /function\s+\w+\s*\([^)]*\)\s*(external|public)/.test(fn.header);
    const isViewOrPure = /\b(view|pure)\b/.test(fn.header);
    const looksStateChanging = /[^=!<>]=(?!=)/.test(fn.body);
    const isConstructor = /^\s*constructor/.test(fn.header);

    if (isExternalOrPublic && !isViewOrPure && looksStateChanging && !isConstructor) {
      const hasGuard =
        hasCustomGuard ||
        /onlyOwner|onlyAdmin|onlyRole/.test(fn.header) ||
        /require\s*\(\s*msg\.sender/.test(fn.header + fn.body.slice(0, 200));
      if (!hasGuard) {
        add(
          "medium",
          "Public/external function without visible access control",
          fn.start,
          `Function "${fn.name}" is public or external, appears to modify state, and has no obvious access-control modifier or msg.sender check near its start.`,
          "Confirm whether this function should be restricted. If so, add an explicit modifier (onlyOwner / role-based) or a require(msg.sender == ...) check."
        );
      }
    }

    if (isExternalOrPublic && !isViewOrPure && looksStateChanging && !/emit\s+\w+/.test(fn.body)) {
      add(
        "info",
        "State-changing function without an emitted event",
        fn.start,
        `Function "${fn.name}" modifies state but doesn't appear to emit an event.`,
        "Consider emitting an event for significant state changes, so off-chain systems can index and monitor them."
      );
    }

    // Shadowed state variables
    ctx.stateVars.forEach((sv) => {
      const shadowRe = new RegExp(
        `\\b(uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|address|bool|string|bytes32)\\s+${sv}\\b`
      );
      if (shadowRe.test(fn.body)) {
        add(
          "medium",
          "Local variable shadows a state variable",
          fn.start,
          `Function "${fn.name}" declares a local variable named "${sv}" — the same name as a state variable. This can mask the state variable and cause unintended reads or writes.`,
          `Rename the local variable to something distinct from the state variable "${sv}".`
        );
      }
    });

    // Uninitialized storage pointer
    forEachMatch(fn.body, /\b([A-Z][a-zA-Z0-9_]*)\s+storage\s+([a-zA-Z_$][\w$]*)\s*;/g, (idx2, mm2) =>
      add(
        "critical",
        "Possibly uninitialized storage pointer",
        fn.start + idx2,
        `"${mm2[2]}" is declared as a storage-located ${mm2[1]} without being assigned on the same line. Uninitialized storage pointers can silently alias storage slot 0 or another unintended slot.`,
        "Assign the storage variable to an existing state variable immediately, or declare it as memory if that's what's actually intended."
      )
    );

    // Unprotected upgradeable initializer
    if (/^initialize$/i.test(fn.name)) {
      const guarded = /\binitializer\b/.test(fn.header) || /require\s*\(\s*!\s*\w*[Ii]nitialized/.test(fn.body);
      if (!guarded) {
        add(
          "high",
          "Unprotected upgradeable initializer",
          fn.start,
          `Function "${fn.name}" looks like an upgradeable-contract initializer but doesn't appear to use an "initializer" modifier or a re-init guard.`,
          "Use OpenZeppelin's initializer modifier (or an explicit boolean guard) so this function can only run once."
        );
      }
    }

    // Arbitrary send to a caller-supplied address
    const addrParamMatch = fn.header.match(/address\s+(?:payable\s+)?([a-zA-Z_$][\w$]*)/);
    if (addrParamMatch) {
      const p = addrParamMatch[1];
      const sendRe = new RegExp(`\\b${p}\\.(transfer|send)\\(|\\b${p}\\.call\\{[^}]*value`);
      const sendMatch = fn.body.match(sendRe);
      if (sendMatch) {
        const before = fn.body.slice(0, fn.body.indexOf(sendMatch[0]));
        const validated = new RegExp(`require\\s*\\([^;]*${p}`).test(before);
        if (!validated) {
          add(
            "high",
            "Arbitrary send to a caller-supplied address",
            fn.start,
            `Function "${fn.name}" sends value to address parameter "${p}" without an obvious require() validating that address first.`,
            `Restrict what "${p}" is allowed to be, or require it to equal msg.sender, so callers can't redirect funds anywhere they choose.`
          );
        }
      }
    }
  });

  // Locked ether: contract accepts value but no function appears to send it back out
  if (/\bpayable\b/.test(code)) {
    const anyWithdraw = functions.some((fn) => /\.transfer\(|\.send\(|\.call\{[^}]*value/.test(fn.body));
    if (!anyWithdraw) {
      add(
        "medium",
        "Contract can receive ether but has no visible withdrawal path",
        1,
        "This contract has payable function(s), but no function in this file appears to send ether back out.",
        "Add a guarded withdraw function, or confirm ether is meant to stay locked (e.g. routed elsewhere) intentionally.",
        true
      );
    }
  }

  // Unused state variables
  ctx.stateVars.forEach((sv) => {
    const occurrences = (code.match(new RegExp(`\\b${sv}\\b`, "g")) || []).length;
    if (occurrences <= 1) {
      add(
        "info",
        "Unused state variable",
        1,
        `State variable "${sv}" doesn't appear to be referenced anywhere else in this file.`,
        "Remove it if unused, or confirm it's referenced in an inherited/imported contract not included here.",
        true
      );
    }
  });

  // Chain 1404 (BlockDAG) compatibility: defaults to Shanghai (PUSH0) on 0.8.20+,
  // but chain 1404 targets Berlin and rejects PUSH0 at deploy time.
  if (pragmaMatch) {
    const verNum2 = pragmaMatch[1].match(/(\d+)\.(\d+)/);
    const isShanghaiDefault = verNum2 && Number(verNum2[1]) === 0 && Number(verNum2[2]) >= 20;
    const evmVersionPinned = /evmVersion\s*[:=]\s*["'`]?(berlin|london|istanbul)/i.test(code);
    if (isShanghaiDefault && !evmVersionPinned) {
      add(
        "medium",
        "Chain 1404 (BlockDAG) EVM-version mismatch risk",
        lineOf(code, pragmaMatch.index),
        "Solidity 0.8.20+ compiles to the Shanghai EVM target by default, which emits the PUSH0 opcode. Chain 1404 (BlockDAG) targets Berlin and doesn't support PUSH0, so a default build can fail silently at deploy time.",
        'Set evmVersion: "berlin" explicitly in your compiler config (hardhat.config.js solidity.settings, or foundry.toml) when targeting chain 1404.'
      );
    }
  }

  forEachMatch(code, /0x[a-fA-F0-9]{40}(?![a-fA-F0-9])/g, (idx) =>
    add(
      "info",
      "Hardcoded address literal",
      idx,
      "A hardcoded 20-byte address literal was found.",
      "Confirm this address is meant to be immutable and is correct for every environment this contract will be deployed to."
    )
  );

  forEachMatch(code, /for\s*\([^)]*\.length[^)]*\)/g, (idx) =>
    add(
      "medium",
      "Loop bound by a dynamic array's length",
      idx,
      "A loop iterates based on a dynamic array's length. If that array can grow without bound, this loop can eventually exceed the block gas limit.",
      "Consider pagination, a pull-payment pattern, or an explicit cap on the array's size."
    )
  );

  return findings;
}

function analyzeFrontend(code, fileName) {
  const findings = [];
  const add = (severity, title, idx, message, recommendation) =>
    findings.push({ file: fileName, severity, title, line: lineOf(code, idx), message, recommendation });

  forEachMatch(code, /0x[a-fA-F0-9]{64}(?![a-fA-F0-9])/g, (idx) =>
    add(
      "critical",
      "Possible hardcoded private key",
      idx,
      "A 32-byte hex string was found, matching the shape of a raw private key.",
      "Never commit private keys. Move it to an environment variable or secrets manager, and rotate the key immediately if it's real."
    )
  );

  forEachMatch(code, /(mnemonic|seedPhrase|seed_phrase)\s*[:=]\s*["'`][a-z ]{40,}["'`]/gi, (idx) =>
    add(
      "critical",
      "Possible hardcoded mnemonic or seed phrase",
      idx,
      "A variable named like a mnemonic/seed phrase is assigned a literal string of words.",
      "Remove this immediately and rotate any wallet that used this seed. Never hardcode seed phrases."
    )
  );

  forEachMatch(code, /(api[_-]?key|secret|private[_-]?key)\s*[:=]\s*["'`][A-Za-z0-9_\-]{12,}["'`]/gi, (idx) =>
    add(
      "high",
      "Possible hardcoded API key or secret",
      idx,
      "A variable named like a key or secret is assigned what looks like a literal credential.",
      "Move secrets to environment variables or a secrets manager. Never ship credentials in client-side code."
    )
  );

  forEachMatch(code, /["'`]http:\/\/[^"'`]+["'`]/g, (idx) =>
    add(
      "medium",
      "Non-HTTPS endpoint",
      idx,
      "A plain http:// URL was found. If this is an RPC endpoint or API host, traffic including request payloads is unencrypted.",
      "Use https:// (and wss:// for websockets) for every network endpoint, especially RPC providers."
    )
  );

  forEachMatch(code, /\beval\s*\(/g, (idx) =>
    add(
      "high",
      "Use of eval()",
      idx,
      "eval() runs arbitrary strings as code, a common injection vector.",
      "Avoid eval(). Use JSON.parse for data, or a safer alternative for dynamic logic."
    )
  );

  forEachMatch(code, /\.innerHTML\s*=/g, (idx) =>
    add(
      "medium",
      "Direct innerHTML assignment",
      idx,
      "Assigning to innerHTML with unsanitized input can lead to cross-site scripting.",
      "Use textContent for plain text, or sanitize HTML (for example with DOMPurify) before inserting it."
    )
  );

  forEachMatch(code, /dangerouslySetInnerHTML/g, (idx) =>
    add(
      "medium",
      "React dangerouslySetInnerHTML",
      idx,
      "dangerouslySetInnerHTML skips React's built-in escaping, which can lead to XSS if the content is user-controlled.",
      "Sanitize the HTML (for example with DOMPurify) before rendering, or avoid raw HTML injection."
    )
  );

  if (/window\.ethereum/.test(code) && !/if\s*\(\s*(window\.ethereum|typeof window\.ethereum)/.test(code)) {
    const idx = code.indexOf("window.ethereum");
    add(
      "low",
      "window.ethereum used without an existence check",
      idx,
      "window.ethereum is referenced without a visible guard, which throws in browsers or environments with no injected wallet.",
      "Check for window.ethereum (or use a wallet-connection library) before using it, and show a fallback UI when it's absent."
    );
  }

  forEachMatch(code, /Math\.random\(\)/g, (idx) => {
    const context = code.slice(Math.max(0, idx - 80), idx).toLowerCase();
    if (/nonce|token|secret|key|session/.test(context)) {
      add(
        "high",
        "Math.random() used in a security-sensitive context",
        idx,
        "Math.random() is not cryptographically secure and its output is predictable.",
        "Use a cryptographically secure source, such as crypto.getRandomValues(), or generate it server-side."
      );
    }
  });

  forEachMatch(code, /localStorage\.setItem\(\s*["'`][^"'`]*(?:key|seed|mnemonic|private)[^"'`]*["'`]/gi, (idx) =>
    add(
      "high",
      "Sensitive-looking data stored in localStorage",
      idx,
      "localStorage is unencrypted and reachable by any script running on the page, including through XSS.",
      "Never store private keys or seed phrases in localStorage. Use a dedicated keystore, or at minimum an encrypted, access-controlled store."
    )
  );

  forEachMatch(code, /process\.env\.\w+\s*\|\|\s*["'`][A-Za-z0-9_\-]{8,}["'`]/g, (idx) =>
    add(
      "medium",
      "Hardcoded fallback for an environment secret",
      idx,
      "An environment variable has a hardcoded literal fallback, which can ship a real secret if the variable is ever unset.",
      "Fail closed instead: validate that the required environment variable is present rather than falling back to a literal."
    )
  );

  forEachMatch(code, /Access-Control-Allow-Origin["'`]?\s*[:=]\s*["'`]\*["'`]/g, (idx) =>
    add(
      "medium",
      "Wildcard CORS origin",
      idx,
      "Access-Control-Allow-Origin is set to *, letting any site make cross-origin requests.",
      "Restrict CORS to a known allow-list of origins, especially for endpoints that handle wallet or authenticated requests."
    )
  );

  forEachMatch(code, /function\s+\w*[Ss]wap\w*\s*\([^)]*\)/g, (idx) => {
    const header = code.slice(idx, idx + 200);
    if (!/deadline|minOut|minAmountOut|slippage/i.test(header)) {
      add(
        "info",
        "Swap-like function without a visible deadline or slippage param",
        idx,
        "A function that looks like a token swap has no obvious deadline or minimum-output parameter nearby.",
        "Confirm slippage and deadline protections exist somewhere in the call path, to guard against sandwich attacks."
      );
    }
  });

  return findings;
}

const SLITHER_IMPACT_MAP = {
  High: "high",
  Medium: "medium",
  Low: "low",
  Informational: "info",
  Optimization: "info",
};

function parseSlitherJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error("That doesn't look like valid JSON. Paste the full output of `slither . --json -`.");
  }
  const detectors = parsed?.results?.detectors;
  if (!Array.isArray(detectors)) {
    throw new Error('No "results.detectors" array found — paste Slither\'s JSON output, not its text output.');
  }
  return detectors.map((d) => {
    const el = d.elements && d.elements[0];
    const file = el?.source_mapping?.filename_short || el?.source_mapping?.filename_relative || "slither target";
    const line = el?.source_mapping?.lines?.[0] || "?";
    return {
      file,
      severity: SLITHER_IMPACT_MAP[d.impact] || "info",
      title: d.check || "Slither finding",
      line,
      message: (d.description || "").trim().replace(/\s+/g, " "),
      recommendation: `See Slither's "${d.check}" detector documentation for the recommended fix.`,
      source: "slither",
    };
  });
}

function computeScore(findings) {
  const deduction = findings.reduce((sum, f) => sum + (SEVERITY_META[f.severity]?.weight || 0), 0);
  return Math.max(0, Math.min(100, Math.round(100 - deduction)));
}

function gradeLabel(score) {
  if (score >= 90) return "A — low risk";
  if (score >= 75) return "B — minor issues";
  if (score >= 55) return "C — needs attention";
  if (score >= 35) return "D — high risk";
  return "F — critical risk";
}

function scoreColor(score) {
  if (score >= 85) return "#3addff";
  if (score >= 60) return "#f5c451";
  return "#ff4d6d";
}

function buildMarkdownReport(entry) {
  const lines = [];
  lines.push("# Auditrace report");
  lines.push("");
  lines.push(`Generated ${new Date(entry.timestamp).toLocaleString()}`);
  lines.push(`Files: ${entry.fileNames.join(", ")}`);
  lines.push("");
  lines.push(`## Score: ${entry.score}/100 — ${entry.grade}`);
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  SEVERITY_ORDER.forEach((s) => lines.push(`| ${SEVERITY_META[s].label} | ${entry.summary[s] || 0} |`));
  lines.push("");
  SEVERITY_ORDER.forEach((s) => {
    const items = entry.findings.filter((f) => f.severity === s);
    if (!items.length) return;
    lines.push(`## ${SEVERITY_META[s].label} (${items.length})`);
    items.forEach((f) => {
      lines.push("");
      lines.push(`### ${f.title}`);
      lines.push(`File: ${f.file}, line ${f.line}`);
      lines.push("");
      lines.push(f.message);
      lines.push("");
      lines.push(`Recommendation: ${f.recommendation}`);
    });
    lines.push("");
  });
  lines.push("---");
  lines.push(
    "Auditrace performs automated static analysis only. It flags known patterns and heuristics, cannot guarantee full coverage, cannot compile or execute your contracts, and is not a substitute for a manual audit by a qualified security engineer before mainnet deployment."
  );
  return lines.join("\n");
}

/* =========================================================================
   UI
   ========================================================================= */

function OrbitMark({ size = 64 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <circle cx="50" cy="50" r="42" fill="none" stroke="#1c2233" strokeWidth="1.2" strokeDasharray="3 5" />
      <line x1="20" y1="20" x2="50" y2="50" stroke="#3addff" strokeWidth="1" opacity="0.8" />
      <line x1="80" y1="20" x2="50" y2="50" stroke="#3addff" strokeWidth="1" opacity="0.8" />
      <line x1="20" y1="80" x2="50" y2="50" stroke="#ff8f6d" strokeWidth="1" opacity="0.8" />
      <line x1="80" y1="80" x2="50" y2="50" stroke="#ff8f6d" strokeWidth="1" opacity="0.8" />
      <circle cx="20" cy="20" r="3.5" fill="#3addff" />
      <circle cx="80" cy="20" r="3.5" fill="#3addff" />
      <circle cx="20" cy="80" r="3.5" fill="#ff8f6d" />
      <circle cx="80" cy="80" r="3.5" fill="#ff8f6d" />
      <text x="50" y="58" textAnchor="middle" fontFamily="'IBM Plex Mono', monospace" fontWeight="700" fontSize="30" fill="#a855f7">
        A
      </text>
    </svg>
  );
}

function ScoreDial({ score }) {
  const r = 68;
  const circumference = 2 * Math.PI * r;
  const frac = score / 100;
  const color = scoreColor(score);
  return (
    <svg width="176" height="176" viewBox="0 0 176 176">
      <circle cx="88" cy="88" r="84" fill="none" stroke="#1c2233" strokeWidth="1.2" strokeDasharray="3 5" />
      <circle cx="88" cy="88" r={r} fill="none" stroke="#10141f" strokeWidth="10" />
      <circle
        cx="88"
        cy="88"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${circumference * frac} ${circumference}`}
        transform="rotate(-90 88 88)"
      />
      <text x="88" y="82" textAnchor="middle" fontFamily="'IBM Plex Mono', monospace" fontWeight="700" fontSize="40" fill="#eef1f7">
        {score}
      </text>
      <text x="88" y="106" textAnchor="middle" fontFamily="'IBM Plex Mono', monospace" fontSize="11" fill="#8b93a7">
        / 100
      </text>
    </svg>
  );
}

function SeverityChip({ sev, count }) {
  const meta = SEVERITY_META[sev];
  return (
    <div className={`chip ${count > 0 ? "chip-on" : ""}`} style={{ "--chip-color": meta.color }}>
      <span className="chip-dot" />
      <span className="chip-label">{meta.label}</span>
      <span className="chip-count">{count}</span>
    </div>
  );
}

function FindingCard({ f }) {
  const meta = SEVERITY_META[f.severity];
  return (
    <details className="finding">
      <summary>
        <span className="finding-dot" style={{ background: meta.color }} />
        <span className="finding-title">{f.title}</span>
        {f.source === "slither" && <span className="source-tag">slither</span>}
        <span className="finding-loc">
          {f.file} · line {f.line}
        </span>
      </summary>
      <div className="finding-body">
        <p>{f.message}</p>
        <p className="finding-rec">
          <strong>Fix:</strong> {f.recommendation}
        </p>
      </div>
    </details>
  );
}

function ResultsPanel({ entry, onDownload }) {
  return (
    <div className="results">
      <div className="disclaimer">
        Automated static analysis only. Auditrace flags known patterns — it can't compile, execute, or guarantee
        full coverage of your code, and isn't a substitute for a manual audit before mainnet deployment.
      </div>

      <div className="score-row">
        <ScoreDial score={entry.score} />
        <div className="score-details">
          <div className="grade">{entry.grade}</div>
          <div className="files-list">
            {entry.fileNames.map((n) => (
              <span key={n} className="file-tag">
                <FileCode2 size={13} /> {n}
              </span>
            ))}
          </div>
          <div className="chips">
            {SEVERITY_ORDER.map((s) => (
              <SeverityChip key={s} sev={s} count={entry.summary[s] || 0} />
            ))}
          </div>
          <button className="btn-outline" onClick={() => onDownload(entry)}>
            <Download size={15} /> Download report
          </button>
        </div>
      </div>

      <div className="findings-list">
        {entry.findings.length === 0 && (
          <div className="empty-good">
            <ShieldCheck size={20} />
            No pattern-based findings. That's a good sign — it isn't a guarantee.
          </div>
        )}
        {SEVERITY_ORDER.map((s) => {
          const items = entry.findings.filter((f) => f.severity === s);
          if (!items.length) return null;
          return (
            <div key={s} className="finding-group">
              <div className="finding-group-title" style={{ "--gcolor": SEVERITY_META[s].color }}>
                {SEVERITY_META[s].label} ({items.length})
              </div>
              {items.map((f, i) => (
                <FindingCard key={i} f={f} />
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const EXPLORERS = [
  { name: "Community Explorer", base: "https://explorer.welshdag.co.uk" },
  { name: "BlockDAG Engineering", base: "https://explorer.blockdag.engineering" },
];

function isLikelyAddress(addr) {
  return /^0x[a-fA-F0-9]{40}$/.test(addr.trim());
}

async function fetchFromOneExplorer(baseUrl, explorerName, address) {
  const url = `${baseUrl}/api/v2/smart-contracts/${address.trim()}`;
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (e) {
    throw new Error(`${explorerName}: couldn't reach it (network error or CORS block).`);
  }
  if (res.status === 404) {
    throw new Error(`${explorerName}: no verified contract found at that address.`);
  }
  if (!res.ok) {
    throw new Error(`${explorerName}: returned HTTP ${res.status}, may be down.`);
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    throw new Error(`${explorerName}: response wasn't valid JSON.`);
  }
  const primary = data.source_code;
  if (!primary) {
    throw new Error(`${explorerName}: contract exists but isn't verified there (no source_code in the response).`);
  }
  const files = [{ name: `${data.name || "Contract"}.sol`, code: primary }];
  if (Array.isArray(data.additional_sources)) {
    data.additional_sources.forEach((s) => {
      if (s.source_code) files.push({ name: s.file_path || `${uid()}.sol`, code: s.source_code });
    });
  }
  return { files, name: data.name, compilerVersion: data.compiler_version };
}

async function fetchVerifiedSource(address) {
  const errors = [];
  for (const explorer of EXPLORERS) {
    try {
      const result = await fetchFromOneExplorer(explorer.base, explorer.name, address);
      return { ...result, explorerName: explorer.name };
    } catch (e) {
      errors.push(e.message);
    }
  }
  throw new Error(errors.join(" "));
}

async function storageGet(key) {
  if (typeof window === "undefined") return null;
  if (window.storage) {
    const res = await window.storage.get(key, false);
    return res ? res.value : null;
  }
  return window.localStorage.getItem(key);
}

async function storageSet(key, value) {
  if (typeof window === "undefined") return false;
  if (window.storage) {
    const res = await window.storage.set(key, value, false);
    return !!res;
  }
  window.localStorage.setItem(key, value);
  return true;
}

const emptyFile = (type, idx) => ({
  id: uid(),
  name: type === "solidity" ? `Contract${idx}.sol` : `app${idx}.js`,
  type,
  code: "",
});

export default function App() {
  const [view, setView] = useState("audit");
  const [files, setFiles] = useState([emptyFile("solidity", 1)]);
  const [result, setResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [detailItem, setDetailItem] = useState(null);
  const [savedNote, setSavedNote] = useState(false);
  const [storageAvailable, setStorageAvailable] = useState(true);
  const [slitherText, setSlitherText] = useState("");
  const [slitherError, setSlitherError] = useState(null);
  const [slitherCount, setSlitherCount] = useState(0);
  const [fetchAddress, setFetchAddress] = useState("");
  const [fetchLoading, setFetchLoading] = useState(false);
  const [fetchError, setFetchError] = useState(null);
  const [fetchOk, setFetchOk] = useState(null);

  useEffect(() => {
    loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadHistory() {
    try {
      const value = await storageGet("audit-history");
      setHistory(value ? JSON.parse(value) : []);
      setStorageAvailable(true);
    } catch (e) {
      setHistory([]);
      setStorageAvailable(false);
    } finally {
      setHistoryLoaded(true);
    }
  }

  async function persistHistory(next) {
    setHistory(next);
    try {
      const ok = await storageSet("audit-history", JSON.stringify(next));
      setStorageAvailable(ok);
    } catch (e) {
      setStorageAvailable(false);
    }
  }

  function addFile(type) {
    setFiles((fs) => [...fs, emptyFile(type, fs.filter((f) => f.type === type).length + 1)]);
  }
  function updateFile(id, patch) {
    setFiles((fs) => fs.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  }
  function removeFile(id) {
    setFiles((fs) => fs.filter((f) => f.id !== id));
  }

  async function fetchFromExplorer() {
    setFetchError(null);
    setFetchOk(null);
    if (!isLikelyAddress(fetchAddress)) {
      setFetchError("That doesn't look like a contract address (expected 0x followed by 40 hex characters).");
      return;
    }
    setFetchLoading(true);
    try {
      const { files: fetched, name, explorerName } = await fetchVerifiedSource(fetchAddress);
      setFiles((fs) => [
        ...fs,
        ...fetched.map((f) => ({ id: uid(), name: f.name, type: "solidity", code: f.code })),
      ]);
      setFetchOk(
        `Loaded ${fetched.length} file${fetched.length === 1 ? "" : "s"} for "${name || fetchAddress}" via ${explorerName}.`
      );
      setFetchAddress("");
    } catch (e) {
      setFetchError(e.message);
    } finally {
      setFetchLoading(false);
    }
  }

  function applySlitherImport() {
    setSlitherError(null);
    if (!slitherText.trim()) {
      setSlitherCount(0);
      return;
    }
    try {
      const parsed = parseSlitherJson(slitherText);
      setSlitherCount(parsed.length);
    } catch (e) {
      setSlitherCount(0);
      setSlitherError(e.message);
    }
  }

  async function runAudit() {
    const active = files.filter((f) => f.code.trim().length > 0);
    if (active.length === 0) return;
    setAnalyzing(true);
    setResult(null);
    setSavedNote(false);
    setSlitherError(null);
    await new Promise((r) => setTimeout(r, 450));

    let findings = [];
    active.forEach((f) => {
      findings = findings.concat(f.type === "solidity" ? analyzeSolidity(f.code, f.name) : analyzeFrontend(f.code, f.name));
    });

    let fileNames = active.map((f) => f.name);
    if (slitherText.trim()) {
      try {
        const slitherFindings = parseSlitherJson(slitherText);
        findings = findings.concat(slitherFindings);
        setSlitherCount(slitherFindings.length);
        fileNames = Array.from(new Set([...fileNames, ...slitherFindings.map((f) => f.file)]));
      } catch (e) {
        setSlitherError(e.message);
        setSlitherCount(0);
      }
    }

    const score = computeScore(findings);
    const summary = SEVERITY_ORDER.reduce((acc, s) => {
      acc[s] = findings.filter((f) => f.severity === s).length;
      return acc;
    }, {});
    const entry = {
      id: uid(),
      timestamp: Date.now(),
      fileNames,
      score,
      grade: gradeLabel(score),
      summary,
      findings,
    };
    setResult(entry);
    setAnalyzing(false);
    const next = [entry, ...history].slice(0, 25);
    await persistHistory(next);
    setSavedNote(true);
  }

  async function deleteHistoryItem(id) {
    const next = history.filter((h) => h.id !== id);
    await persistHistory(next);
    if (detailItem && detailItem.id === id) {
      setDetailItem(null);
      setView("history");
    }
  }

  async function clearHistory() {
    await persistHistory([]);
  }

  function downloadReport(entry) {
    const md = buildMarkdownReport(entry);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `auditrace-${entry.id}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const canRun = files.some((f) => f.code.trim().length > 0);

  return (
    <div className="auditrace-app">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap');

        html, body {
          margin: 0;
          padding: 0;
          background: #05070c;
        }
        #root {
          min-height: 100vh;
        }

        .auditrace-app {
          --void: #05070c;
          --panel: #0b0e16;
          --panel-2: #10141f;
          --line: #1c2233;
          --text: #eef1f7;
          --muted: #8b93a7;
          --purple: #a855f7;
          --cyan: #3addff;
          --coral: #ff8f6d;
          --amber: #f5c451;
          --danger: #ff4d6d;
          position: relative;
          background: var(--void);
          color: var(--text);
          font-family: 'Inter', system-ui, sans-serif;
          min-height: 100vh;
          padding: 28px 20px 72px;
          box-sizing: border-box;
          overflow-x: hidden;
        }
        .auditrace-app::before {
          content: "";
          position: fixed;
          inset: 0;
          z-index: -1;
          pointer-events: none;
          background-color: var(--void);
          background-image:
            radial-gradient(2.5px 2.5px at 8% 12%, #ffffff, transparent 100%),
            radial-gradient(1.5px 1.5px at 22% 28%, rgba(255,255,255,0.85), transparent 100%),
            radial-gradient(3px 3px at 36% 6%, #ffffff, transparent 100%),
            radial-gradient(1.5px 1.5px at 52% 22%, rgba(58,221,255,0.9), transparent 100%),
            radial-gradient(2.2px 2.2px at 68% 9%, #ffffff, transparent 100%),
            radial-gradient(1.5px 1.5px at 81% 31%, rgba(255,255,255,0.8), transparent 100%),
            radial-gradient(2.8px 2.8px at 91% 4%, rgba(168,85,247,0.95), transparent 100%),
            radial-gradient(1.5px 1.5px at 14% 45%, rgba(255,255,255,0.8), transparent 100%),
            radial-gradient(2.5px 2.5px at 29% 58%, #ffffff, transparent 100%),
            radial-gradient(1.6px 1.6px at 45% 67%, rgba(58,221,255,0.85), transparent 100%),
            radial-gradient(2px 2px at 59% 49%, rgba(255,255,255,0.85), transparent 100%),
            radial-gradient(1.5px 1.5px at 73% 72%, rgba(255,255,255,0.75), transparent 100%),
            radial-gradient(2.8px 2.8px at 87% 55%, #ffffff, transparent 100%),
            radial-gradient(1.5px 1.5px at 6% 81%, rgba(255,255,255,0.8), transparent 100%),
            radial-gradient(2.3px 2.3px at 24% 90%, rgba(168,85,247,0.85), transparent 100%),
            radial-gradient(1.6px 1.6px at 41% 84%, rgba(255,255,255,0.9), transparent 100%),
            radial-gradient(2.6px 2.6px at 63% 93%, #ffffff, transparent 100%),
            radial-gradient(1.6px 1.6px at 78% 88%, rgba(58,221,255,0.8), transparent 100%),
            radial-gradient(2.2px 2.2px at 95% 77%, rgba(255,255,255,0.85), transparent 100%),
            radial-gradient(1.4px 1.4px at 3% 65%, rgba(255,255,255,0.6), transparent 100%),
            radial-gradient(1.8px 1.8px at 17% 3%, rgba(255,255,255,0.7), transparent 100%),
            radial-gradient(1.4px 1.4px at 33% 38%, rgba(58,221,255,0.6), transparent 100%),
            radial-gradient(1.8px 1.8px at 48% 12%, rgba(255,255,255,0.65), transparent 100%),
            radial-gradient(1.4px 1.4px at 57% 78%, rgba(255,255,255,0.6), transparent 100%),
            radial-gradient(1.8px 1.8px at 71% 40%, rgba(168,85,247,0.6), transparent 100%),
            radial-gradient(1.4px 1.4px at 84% 20%, rgba(255,255,255,0.65), transparent 100%),
            radial-gradient(1.8px 1.8px at 98% 60%, rgba(255,255,255,0.6), transparent 100%),
            radial-gradient(1.4px 1.4px at 11% 96%, rgba(255,255,255,0.6), transparent 100%),
            radial-gradient(1.8px 1.8px at 39% 96%, rgba(58,221,255,0.55), transparent 100%),
            radial-gradient(1.4px 1.4px at 54% 33%, rgba(255,255,255,0.55), transparent 100%),
            radial-gradient(ellipse 1100px 800px at 15% -10%, rgba(140,70,220,0.32), transparent 62%),
            radial-gradient(ellipse 1000px 800px at 102% 108%, rgba(25,140,190,0.28), transparent 62%);
          background-repeat: no-repeat;
          animation: twinkle 5s ease-in-out infinite alternate;
        }
        @keyframes twinkle {
          from { opacity: 0.65; }
          to { opacity: 1; }
        }
        .auditrace-app * { box-sizing: border-box; }
        .mono { font-family: 'IBM Plex Mono', ui-monospace, monospace; }

        .shell { max-width: 880px; margin: 0 auto; }

        .header {
          display: flex; align-items: center; justify-content: space-between;
          gap: 16px; margin-bottom: 28px; flex-wrap: wrap;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand-text .name {
          font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 20px;
          letter-spacing: 0.02em; color: var(--text); line-height: 1.1;
        }
        .brand-text .by { font-size: 12px; color: var(--muted); margin-top: 2px; }
        .nav { display: flex; gap: 4px; background: var(--panel); border: 1px solid var(--line); padding: 4px; border-radius: 10px; }
        .nav button {
          font-family: 'IBM Plex Mono', monospace; font-size: 13px; padding: 8px 14px;
          background: transparent; border: none; color: var(--muted); border-radius: 7px; cursor: pointer;
          display: flex; align-items: center; gap: 6px; transition: color .15s ease, background .15s ease;
        }
        .nav button.active { background: var(--panel-2); color: var(--text); }
        .nav button:hover:not(.active) { color: var(--text); }

        .hero { display: flex; align-items: center; gap: 24px; padding: 28px 8px 32px; border-bottom: 1px solid var(--line); margin-bottom: 28px; }
        .hero h1 { font-family: 'IBM Plex Mono', monospace; font-size: 22px; font-weight: 600; margin: 0 0 8px; }
        .hero p { color: var(--muted); font-size: 14.5px; line-height: 1.55; max-width: 50ch; margin: 0; }
        .hero .accent { color: var(--purple); }

        .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        .panel-title { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: var(--muted); margin-bottom: 14px; }

        .file-card { border: 1px solid var(--line); border-radius: 10px; margin-bottom: 12px; overflow: hidden; }
        .file-card-head { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--panel-2); }
        .file-type-badge {
          font-family: 'IBM Plex Mono', monospace; font-size: 11px; padding: 3px 8px; border-radius: 5px;
          border: 1px solid var(--line); color: var(--cyan); flex-shrink: 0;
        }
        .file-type-badge.js { color: var(--coral); }
        .file-name-input {
          background: transparent; border: none; color: var(--text); font-family: 'IBM Plex Mono', monospace;
          font-size: 13px; flex: 1; outline: none; min-width: 0;
        }
        .file-remove { background: transparent; border: none; color: var(--muted); cursor: pointer; padding: 4px; border-radius: 6px; }
        .file-remove:hover { color: var(--danger); }
        .file-code {
          width: 100%; background: var(--void); color: var(--text); border: none; outline: none;
          font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; line-height: 1.6; padding: 12px;
          min-height: 140px; resize: vertical;
        }
        .file-code::placeholder { color: #4a5164; }

        .add-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }
        .btn-add {
          display: flex; align-items: center; gap: 6px; background: transparent; border: 1px dashed var(--line);
          color: var(--muted); font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; padding: 9px 12px;
          border-radius: 8px; cursor: pointer;
        }
        .btn-add:hover { color: var(--text); border-color: #333c54; }

        .run-row { display: flex; align-items: center; gap: 14px; margin-top: 18px; }
        .btn-primary {
          font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 13.5px;
          background: var(--purple); color: #17061f; border: none; padding: 12px 20px; border-radius: 9px;
          cursor: pointer; display: flex; align-items: center; gap: 8px;
        }
        .btn-primary:disabled { background: var(--line); color: var(--muted); cursor: not-allowed; }
        .btn-outline {
          font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; background: transparent; color: var(--text);
          border: 1px solid var(--line); padding: 9px 14px; border-radius: 8px; cursor: pointer;
          display: flex; align-items: center; gap: 7px;
        }
        .btn-outline:hover { border-color: var(--cyan); color: var(--cyan); }
        .hint { color: var(--muted); font-size: 12.5px; }
        .saved-note { color: var(--cyan); font-size: 12.5px; font-family: 'IBM Plex Mono', monospace; }

        .results { margin-top: 8px; }
        .disclaimer {
          border: 1px solid var(--line); border-left: 3px solid var(--amber); background: var(--panel);
          color: var(--muted); font-size: 12.5px; line-height: 1.6; padding: 12px 14px; border-radius: 8px; margin-bottom: 22px;
        }
        .score-row { display: flex; gap: 28px; align-items: center; flex-wrap: wrap; margin-bottom: 26px; }
        .score-details { flex: 1; min-width: 220px; }
        .grade { font-family: 'IBM Plex Mono', monospace; font-size: 15px; margin-bottom: 12px; }
        .files-list { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
        .file-tag {
          font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--muted); border: 1px solid var(--line);
          border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;
        }
        .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
        .chip {
          display: flex; align-items: center; gap: 6px; border: 1px solid var(--line); border-radius: 20px;
          padding: 5px 10px 5px 8px; opacity: 0.45;
        }
        .chip.chip-on { opacity: 1; border-color: color-mix(in srgb, var(--chip-color) 55%, var(--line)); }
        .chip-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--chip-color); }
        .chip-label { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--muted); }
        .chip-count { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--text); font-weight: 600; }

        .empty-good { display: flex; align-items: center; gap: 10px; color: var(--cyan); font-size: 13.5px; padding: 16px 4px; }

        .finding-group { margin-bottom: 18px; }
        .finding-group-title {
          font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; color: var(--gcolor); margin-bottom: 8px;
        }
        .finding { border: 1px solid var(--line); border-radius: 8px; margin-bottom: 8px; background: var(--panel); overflow: hidden; }
        .finding summary {
          list-style: none; cursor: pointer; padding: 11px 13px; display: flex; align-items: center; gap: 10px;
        }
        .finding summary::-webkit-details-marker { display: none; }
        .finding-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
        .finding-title { font-size: 13.5px; flex: 1; }
        .finding-loc { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--muted); flex-shrink: 0; }
        .source-tag {
          font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: var(--purple);
          border: 1px solid color-mix(in srgb, var(--purple) 45%, var(--line)); border-radius: 4px;
          padding: 1px 6px; flex-shrink: 0;
        }
        .import-box { border: 1px dashed var(--line); border-radius: 10px; padding: 14px; margin-top: 4px; }
        .import-box textarea {
          width: 100%; background: var(--void); color: var(--text); border: 1px solid var(--line);
          border-radius: 8px; font-family: 'IBM Plex Mono', monospace; font-size: 12px; padding: 10px;
          min-height: 80px; margin-top: 10px;
        }
        .import-error { color: var(--danger); font-size: 12px; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }
        .import-ok { color: var(--cyan); font-size: 12px; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }
        .fetch-row { display: flex; gap: 10px; }
        .fetch-input {
          flex: 1; background: var(--void); border: 1px solid var(--line); color: var(--text);
          font-family: 'IBM Plex Mono', monospace; font-size: 13px; padding: 10px 12px; border-radius: 8px; outline: none;
        }
        .fetch-input:focus { border-color: var(--cyan); }
        .finding-body { padding: 0 13px 14px 30px; }
        .finding-body p { font-size: 13px; line-height: 1.6; color: var(--muted); margin: 6px 0; }
        .finding-rec strong { color: var(--text); }

        .history-item {
          display: flex; align-items: center; gap: 14px; padding: 14px 16px; border: 1px solid var(--line);
          border-radius: 10px; margin-bottom: 10px; cursor: pointer; background: var(--panel);
        }
        .history-item:hover { border-color: #333c54; }
        .history-score {
          font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 16px; width: 42px; text-align: center;
        }
        .history-meta { flex: 1; min-width: 0; }
        .history-files { font-size: 13px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .history-date { font-size: 11.5px; color: var(--muted); margin-top: 2px; }
        .history-del { background: transparent; border: none; color: var(--muted); cursor: pointer; padding: 6px; }
        .history-del:hover { color: var(--danger); }

        .empty-state { color: var(--muted); font-size: 13.5px; text-align: center; padding: 48px 20px; }
        .top-actions { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
        .back-btn { display: flex; align-items: center; gap: 6px; background: transparent; border: none; color: var(--muted); cursor: pointer; font-family: 'IBM Plex Mono', monospace; font-size: 13px; }
        .back-btn:hover { color: var(--text); }

        @media (max-width: 520px) {
          .score-row { flex-direction: column; align-items: flex-start; }
        }
      `}</style>

      <div className="shell">
        <div className="header">
          <div className="brand">
            <OrbitMark size={48} />
            <div className="brand-text">
              <div className="name">auditrace</div>
              <div className="by">by benji projects</div>
            </div>
          </div>
          <div className="nav">
            <button
              className={view === "audit" ? "active" : ""}
              onClick={() => {
                setView("audit");
                setDetailItem(null);
              }}
            >
              <ShieldCheck size={14} /> New audit
            </button>
            <button
              className={view === "history" || view === "detail" ? "active" : ""}
              onClick={() => setView("history")}
            >
              <HistoryIcon size={14} /> History{history.length ? ` (${history.length})` : ""}
            </button>
          </div>
        </div>

        {view === "audit" && (
          <>
            <div className="hero">
              <OrbitMark size={72} />
              <div>
                <h1>
                  Trace the risk before someone else does<span className="accent">.</span>
                </h1>
                <p>
                  Paste Solidity contracts and dapp/frontend code below. Auditrace scans for known vulnerability
                  patterns and scores what it finds — entirely in your browser, nothing is sent anywhere. It's a
                  first pass, not a replacement for a real security audit.
                </p>
              </div>
            </div>

            <div className="panel">
              <div className="panel-title">Fetch a deployed contract (optional)</div>
              <p className="hint" style={{ lineHeight: 1.6, marginBottom: 10 }}>
                Tries a community Blockscout explorer first, then falls back to BlockDAG Engineering's if that one's
                down or the contract isn't verified there. Both are community/fork chains — neither is confirmed to
                be the official BlockDAG mainnet explorer. Only works if the contract is verified on one of them.
              </p>
              <div className="fetch-row">
                <input
                  className="fetch-input"
                  value={fetchAddress}
                  onChange={(e) => {
                    setFetchAddress(e.target.value);
                    setFetchError(null);
                  }}
                  placeholder="0x…"
                  spellCheck={false}
                />
                <button className="btn-outline" disabled={fetchLoading} onClick={fetchFromExplorer}>
                  {fetchLoading ? <Loader2 size={14} className="spin" /> : null}
                  {fetchLoading ? "Fetching…" : "Fetch source"}
                </button>
              </div>
              {fetchError && <div className="import-error">{fetchError}</div>}
              {fetchOk && !fetchError && <div className="import-ok">{fetchOk}</div>}
            </div>

            <div className="panel">
              <div className="panel-title">Files to scan</div>
              {files.map((f) => (
                <div className="file-card" key={f.id}>
                  <div className="file-card-head">
                    <span className={`file-type-badge ${f.type === "javascript" ? "js" : ""}`}>
                      {f.type === "solidity" ? "solidity" : "frontend"}
                    </span>
                    <input
                      className="file-name-input"
                      value={f.name}
                      onChange={(e) => updateFile(f.id, { name: e.target.value })}
                      aria-label="File name"
                    />
                    <button className="file-remove" onClick={() => removeFile(f.id)} aria-label="Remove file">
                      <X size={15} />
                    </button>
                  </div>
                  <textarea
                    className="file-code"
                    value={f.code}
                    onChange={(e) => updateFile(f.id, { code: e.target.value })}
                    placeholder={
                      f.type === "solidity"
                        ? "// paste your Solidity contract here"
                        : "// paste your dapp / frontend code here"
                    }
                    spellCheck={false}
                  />
                </div>
              ))}
              <div className="add-row">
                <button className="btn-add" onClick={() => addFile("solidity")}>
                  <Plus size={13} /> Add Solidity contract
                </button>
                <button className="btn-add" onClick={() => addFile("javascript")}>
                  <Plus size={13} /> Add frontend / dapp file
                </button>
              </div>

              <details className="import-box">
                <summary style={{ cursor: "pointer", fontFamily: "'IBM Plex Mono', monospace", fontSize: "12.5px", color: "var(--muted)" }}>
                  Import real Slither results (optional)
                </summary>
                <p className="hint" style={{ marginTop: 8, lineHeight: 1.6 }}>
                  Run <code>slither . --json -</code> on your own machine (needs Python + <code>pip install slither-analyzer</code> and
                  network access, neither of which this browser tool has) and paste the JSON output here. It'll be merged into the
                  report below, tagged "slither", alongside Auditrace's own pattern scan.
                </p>
                <textarea
                  value={slitherText}
                  onChange={(e) => {
                    setSlitherText(e.target.value);
                    setSlitherError(null);
                  }}
                  onBlur={applySlitherImport}
                  placeholder='{"success": true, "results": {"detectors": [...]}}'
                  spellCheck={false}
                />
                {slitherError && <div className="import-error">{slitherError}</div>}
                {!slitherError && slitherCount > 0 && (
                  <div className="import-ok">
                    {slitherCount} Slither finding{slitherCount === 1 ? "" : "s"} ready to merge in.
                  </div>
                )}
              </details>

              <div className="run-row">
                <button className="btn-primary" disabled={!canRun || analyzing} onClick={runAudit}>
                  {analyzing ? <Loader2 size={15} className="spin" /> : <ShieldCheck size={15} />}
                  {analyzing ? "Analyzing…" : "Run audit"}
                </button>
                {!canRun && <span className="hint">Add some code above to run an audit.</span>}
                {savedNote && !analyzing && <span className="saved-note">Saved to history</span>}
              </div>
            </div>

            {result && (
              <div className="panel">
                <ResultsPanel entry={result} onDownload={downloadReport} />
              </div>
            )}
          </>
        )}

        {view === "history" && (
          <div className="panel">
            <div className="top-actions">
              <div className="panel-title" style={{ marginBottom: 0 }}>
                Past audits
              </div>
              {history.length > 0 && (
                <button className="btn-outline" onClick={clearHistory}>
                  <Trash2 size={13} /> Clear all
                </button>
              )}
            </div>
            {!storageAvailable && (
              <div className="hint" style={{ marginBottom: 14 }}>
                History storage isn't available in this browser — audits won't persist after you close this session.
              </div>
            )}
            {historyLoaded && history.length === 0 && (
              <div className="empty-state">No audits yet. Run one from "New audit" and it'll show up here.</div>
            )}
            {history.map((h) => (
              <div
                key={h.id}
                className="history-item"
                onClick={() => {
                  setDetailItem(h);
                  setView("detail");
                }}
              >
                <div className="history-score mono" style={{ color: scoreColor(h.score) }}>
                  {h.score}
                </div>
                <div className="history-meta">
                  <div className="history-files">{h.fileNames.join(", ")}</div>
                  <div className="history-date">{new Date(h.timestamp).toLocaleString()}</div>
                </div>
                <button
                  className="history-del"
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteHistoryItem(h.id);
                  }}
                  aria-label="Delete audit"
                >
                  <Trash2 size={15} />
                </button>
              </div>
            ))}
          </div>
        )}

        {view === "detail" && detailItem && (
          <div className="panel">
            <div className="top-actions">
              <button className="back-btn" onClick={() => setView("history")}>
                <ArrowLeft size={14} /> Back to history
              </button>
              <button className="history-del" onClick={() => deleteHistoryItem(detailItem.id)} aria-label="Delete audit">
                <Trash2 size={15} />
              </button>
            </div>
            <ResultsPanel entry={detailItem} onDownload={downloadReport} />
          </div>
        )}
      </div>

      <style>{`
        .spin { animation: spin 0.9s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
