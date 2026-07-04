function debugEntryMatches(entry, event, expected) {
  return Object.entries({ event, ...expected }).every(
    ([key, value]) => entry?.[key] === value
  );
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function waitForWebAuthnDebugEvent(
  readDebugEntries,
  event,
  expected = {},
  options = {}
) {
  const label = options.label ?? "WebAuthn debug";
  const timeoutMs = options.timeoutMs ?? 3_000;
  const intervalMs = options.intervalMs ?? 50;
  const deadline = Date.now() + timeoutMs;
  let lastEntries = [];

  for (;;) {
    lastEntries = await readDebugEntries();
    if (lastEntries.some((entry) => debugEntryMatches(entry, event, expected))) {
      return;
    }

    if (Date.now() >= deadline) {
      throw new Error(
        `${label} did not record ${event}: ${JSON.stringify(lastEntries, null, 2)}`
      );
    }

    await delay(Math.min(intervalMs, Math.max(0, deadline - Date.now())));
  }
}
