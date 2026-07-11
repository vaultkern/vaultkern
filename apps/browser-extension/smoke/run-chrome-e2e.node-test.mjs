import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  REQUIRED_CHROMIUM_CASES,
  assertNativeCrashObservation,
  assertNativeReceiptReplay,
  assertPendingSessionSecurityProof,
  assertRestoredPendingMatches,
  automaticAttemptCompleteDiagnostic,
  createControlledResourceGate,
  createManualFillEntryDetailMessage,
  createNativeCrashWrapperScript,
  parseRequestedCases
} from "./run-chrome-e2e.mjs";

test("no arguments select every required Chromium case", () => {
  assert.deepEqual(parseRequestedCases([]), REQUIRED_CHROMIUM_CASES);
  assert.deepEqual(
    REQUIRED_CHROMIUM_CASES,
    [
      "native-kdbx-totp-passkey",
      "exact-origin-automatic-authorization",
      "autofill-shadow-visibility",
      "dynamic-shadow-submit",
      "nested-dynamic-shadow-submit",
      "trusted-spa-submit",
      "controlled-react-input",
      "large-dom-performance",
      "mv3-pending-session-reload",
      "autofill-native-crash-replay"
    ]
  );
});

test("native crash wrapper safely logs its PID, exports the marker, and execs quoted paths", {
  skip: process.platform === "win32" ? "POSIX wrapper" : false
}, async () => {
  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-wrapper-' quoted "));
  try {
    const runtimePath = join(workDir, "fake ' runtime");
    const pidLogPath = join(workDir, "native ' pids.log");
    const crashMarkerPath = join(workDir, "source ' committed.marker");
    const wrapperPath = join(workDir, "native ' wrapper");
    await writeFile(
      runtimePath,
      `#!/bin/sh\nset -eu\nprintf '%s' "$VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER" > "$VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER.observed"\nprintf '%s' "$$" > "$VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER.runtime-pid"\nprintf '%s\\n' "$@" > "$VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER.args"\n`,
      "utf8"
    );
    await chmod(runtimePath, 0o700);
    await writeFile(
      wrapperPath,
      createNativeCrashWrapperScript({ runtimePath, pidLogPath, crashMarkerPath }),
      "utf8"
    );
    await chmod(wrapperPath, 0o700);

    const runtimeArguments = [
      "chrome-extension://quoted-extension/",
      "--parent-window=0"
    ];
    const result = spawnSync(wrapperPath, runtimeArguments, { encoding: "utf8" });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(await readFile(`${crashMarkerPath}.observed`, "utf8"), crashMarkerPath);
    assert.equal(
      (await readFile(pidLogPath, "utf8")).trim(),
      (await readFile(`${crashMarkerPath}.runtime-pid`, "utf8")).trim()
    );
    assert.deepEqual(
      (await readFile(`${crashMarkerPath}.args`, "utf8")).trim().split("\n"),
      runtimeArguments
    );
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test("native receipt replay proof binds every durable response field", () => {
  const valid = {
    type: "autofill_persist_result",
    transactionId: "transaction-native-crash",
    operationId: "operation-native-crash",
    vaultId: "vault-native-crash",
    outcome: "durable",
    disposition: "replayed",
    entryId: "entry-native-crash",
    durability: "source",
    cacheState: "not_applicable",
    committedFingerprint: {
      contentSha256: "ab".repeat(32),
      sizeBytes: 4096
    },
    mergeSummary: null,
    receiptVersion: 1
  };
  const proof = {
    receiptReplay: valid,
    transactionId: valid.transactionId,
    operationId: valid.operationId,
    vaultId: valid.vaultId,
    entryId: valid.entryId,
    sourceContentSha256: valid.committedFingerprint.contentSha256,
    sourceSizeBytes: valid.committedFingerprint.sizeBytes
  };

  assert.deepEqual(assertNativeReceiptReplay(proof), valid);
  for (const receiptReplay of [
    { ...valid, cacheState: "write_failed" },
    {
      ...valid,
      committedFingerprint: { ...valid.committedFingerprint, contentSha256: "cd".repeat(32) }
    },
    {
      ...valid,
      committedFingerprint: { ...valid.committedFingerprint, sizeBytes: 4097 }
    },
    { ...valid, mergeSummary: { mergedEntries: 1, historySnapshotsAdded: 0 } },
    { ...valid, receiptVersion: 2 }
  ]) {
    assert.throws(
      () => assertNativeReceiptReplay({ ...proof, receiptReplay }),
      /did not replay exactly/
    );
  }
});

test("native crash proof requires a disconnected first attempt, durable marker, and new PID", () => {
  const transactionId = "transaction-native-crash";
  const operationId = "operation-native-crash";
  const valid = {
    firstExecution: {
      ok: false,
      pending: { state: "persisting", transactionId, operationId },
      error: { code: "native_port_disconnected", message: "Native host has exited." }
    },
    markerContent: `${transactionId}:${operationId}\n`,
    pidLog: "4101\n4102\n",
    transactionId,
    operationId
  };

  assert.deepEqual(assertNativeCrashObservation(valid), {
    markerBinding: `${transactionId}:${operationId}`,
    firstPid: 4101,
    recoveryPid: 4102,
    nativePids: [4101, 4102],
    disconnectCode: "native_port_disconnected"
  });
  assert.throws(
    () =>
      assertNativeCrashObservation({
        ...valid,
        firstExecution: { ...valid.firstExecution, error: { code: "native_timeout" } }
      }),
    /did not disconnect/
  );
  assert.throws(
    () => assertNativeCrashObservation({ ...valid, pidLog: "4101\n4101\n" }),
    /distinct native process/
  );
  assert.throws(
    () =>
      assertNativeCrashObservation({
        ...valid,
        markerContent: `${valid.markerContent}\n`
      }),
    /did not bind/
  );
});

test("one or more named cases are selected in argument order", () => {
  assert.deepEqual(
    parseRequestedCases([
      "--case",
      "large-dom-performance",
      "--case",
      "trusted-spa-submit"
    ]),
    ["large-dom-performance", "trusted-spa-submit"]
  );
});

test("unknown cases, missing values, and stray arguments fail closed", () => {
  assert.throws(
    () => parseRequestedCases(["--case", "not-a-real-case"]),
    /unknown Chromium case/
  );
  assert.throws(() => parseRequestedCases(["--case"]), /requires a case name/);
  assert.throws(
    () => parseRequestedCases(["large-dom-performance"]),
    /unexpected argument/
  );
  assert.throws(
    () => parseRequestedCases(["--case", "--case"]),
    /requires a case name/
  );
});

test("manual fixture messages require and bind a non-empty entry id", () => {
  assert.throws(
    () =>
      createManualFillEntryDetailMessage(
        "https://example.test/login",
        "",
        { password: "secret" }
      ),
    /non-empty entryId/
  );
  assert.deepEqual(
    createManualFillEntryDetailMessage(
      "https://example.test/login",
      "entry-7",
      { username: "alice", password: "secret" }
    ),
    {
      type: "fill_entry_detail",
      username: "alice",
      password: "secret",
      targetUrl: "https://example.test/login",
      fillCapability: {
        kind: "manual",
        targetUrl: "https://example.test/login",
        entryId: "entry-7"
      }
    }
  );
});

test("controlled resource gate holds load completion until the harness releases it", async () => {
  const calls = [];
  const response = {
    writeHead(status, headers) {
      calls.push(["writeHead", status, headers]);
    },
    end() {
      calls.push(["end"]);
    }
  };
  const gate = createControlledResourceGate();

  const requestId = gate.hold(response);
  assert.equal(await gate.waitForBlocked(), requestId);
  assert.deepEqual(calls, []);

  gate.release(requestId);
  assert.deepEqual(calls, [
    ["writeHead", 204, { "cache-control": "no-store" }],
    ["end"]
  ]);
  assert.throws(() => gate.release(requestId), /not blocked/);
});

test("automatic completion requires the exact terminal background attempt identity", () => {
  const expected = {
    tabId: 17,
    pageUrl: "http://auth.example.test:4101/login",
    afterSequence: 4,
    expectedOutcome: "candidate_rejected"
  };

  assert.equal(
    automaticAttemptCompleteDiagnostic([], expected),
    null
  );
  assert.equal(
    automaticAttemptCompleteDiagnostic(
      [
        {
          event: "page_load_autofill_attempt_complete",
          sequence: 4,
          tabId: expected.tabId,
          targetUrl: expected.pageUrl,
          outcome: "candidate_rejected"
        }
      ],
      expected
    ),
    null
  );
  assert.deepEqual(
    automaticAttemptCompleteDiagnostic(
      [
        {
          at: "2026-07-10T12:00:00.000Z",
          event: "page_load_autofill_attempt_complete",
          sequence: 5,
          tabId: expected.tabId,
          targetUrl: expected.pageUrl,
          outcome: "candidate_rejected"
        }
      ],
      expected
    ),
    {
      event: "automatic-attempt-complete",
      sequence: 5,
      outcome: "candidate_rejected",
      tabId: 17,
      targetUrl: expected.pageUrl,
      backgroundEventAt: "2026-07-10T12:00:00.000Z"
    }
  );
  assert.throws(
    () =>
      automaticAttemptCompleteDiagnostic(
        [
          {
            event: "page_load_autofill_attempt_complete",
            sequence: 5,
            tabId: expected.tabId,
            targetUrl: expected.pageUrl,
            outcome: "delivered"
          }
        ],
        expected
      ),
    /unexpected outcome/
  );
});

test("pending session security proof requires the key, no durable copy, and denied isolated access", () => {
  const key = "vaultkernPendingAutofillTransaction:17";
  const pending = {
    version: 2,
    transactionId: "transaction-123456789",
    state: "captured",
    tabId: 17,
    origin: "https://example.test",
    submission: {
      url: "https://example.test/login",
      username: "alice@example.test",
      password: "secret",
      submittedAt: Date.now()
    },
    expiresAt: Date.now() + 60_000
  };
  const validProof = {
    snapshot: { key, items: { [key]: pending }, pending },
    durableStorage: { local: { settings: true }, sync: {} },
    isolatedStorage: {
      readable: false,
      hasPendingKey: false,
      error: "Access to storage is not allowed from this context."
    }
  };

  assert.deepEqual(
    assertPendingSessionSecurityProof(validProof, { key, pending }),
    {
      pendingSessionKey: key,
      pendingSessionKeys: [key],
      durableStorageKeys: { local: ["settings"], sync: [] },
      isolatedStorage: validProof.isolatedStorage
    }
  );
  const pendingWithExtraField = {
    ...pending,
    unexpected: "changed-after-restart"
  };
  assert.throws(
    () =>
      assertPendingSessionSecurityProof(
        {
          ...validProof,
          snapshot: {
            key,
            items: { [key]: pendingWithExtraField },
            pending: pendingWithExtraField
          }
        },
        { key, pending }
      ),
    /restored pending transaction changed/
  );
  assert.throws(
    () =>
      assertPendingSessionSecurityProof(
        {
          ...validProof,
          durableStorage: { local: { [key]: pending }, sync: {} }
        },
        { key, pending }
      ),
    /local storage retained pending secrets/
  );
  assert.throws(
    () =>
      assertPendingSessionSecurityProof(
        {
          ...validProof,
          isolatedStorage: {
            readable: true,
            hasPendingKey: false,
            items: {}
          }
        },
        { key, pending }
      ),
    /isolated world retained session access/
  );
});

test("restored pending comparison requires exact deep data without key-order dependence", () => {
  const expected = {
    version: 2,
    state: "planned",
    plan: {
      mode: "update",
      desiredFields: {
        username: "alice@example.test",
        password: "secret"
      }
    }
  };
  const reordered = {
    plan: {
      desiredFields: {
        password: "secret",
        username: "alice@example.test"
      },
      mode: "update"
    },
    state: "planned",
    version: 2
  };

  assert.doesNotThrow(() =>
    assertRestoredPendingMatches(reordered, expected, "recovery popup")
  );
  assert.throws(
    () =>
      assertRestoredPendingMatches(
        { ...reordered, unexpected: "changed-after-restart" },
        expected,
        "recovery popup"
      ),
    /recovery popup changed: .*"before".*"restored"/
  );
  assert.throws(
    () =>
      assertRestoredPendingMatches(
        {
          ...reordered,
          plan: {
            ...reordered.plan,
            unexpected: "changed-after-restart"
          }
        },
        expected,
        "recovery popup"
      ),
    /recovery popup changed: .*"before".*"restored"/
  );
  assert.throws(
    () =>
      assertRestoredPendingMatches(
        {
          ...reordered,
          plan: {
            ...reordered.plan,
            desiredFields: {
              ...reordered.plan.desiredFields,
              password: "changed-after-restart"
            }
          }
        },
        expected,
        "recovery popup"
      ),
    /recovery popup changed: .*"before".*"restored"/
  );
});
