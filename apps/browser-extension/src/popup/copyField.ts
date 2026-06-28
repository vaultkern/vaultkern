export async function copyFieldValue(value: string, clearClipboardSeconds = 0) {
  await navigator.clipboard.writeText(value);

  if (clearClipboardSeconds <= 0) {
    return;
  }

  window.setTimeout(() => {
    void navigator.clipboard.writeText("");
  }, clearClipboardSeconds * 1000);
}
