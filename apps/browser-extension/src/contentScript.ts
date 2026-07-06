import { applyFillPlan } from "./autofill/applyFillPlan";
import { collectAutofillPageSnapshot } from "./autofill/collectPageFields";
import { createLoginFillPlan } from "./autofill/fillPlan";

export function fillLoginForm(payload: {
  username?: string;
  password?: string;
}) {
  const snapshot = collectAutofillPageSnapshot(document);
  const fillPlan = createLoginFillPlan(snapshot, payload);
  applyFillPlan(fillPlan, document);
}

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: { type?: string; username?: string; password?: string },
      _sender: unknown,
      _sendResponse: (response?: unknown) => void
    ) => {
      if (message.type !== "fill_entry_detail") {
        return false;
      }

      const hasUsername = typeof message.username === "string";
      const hasPassword = typeof message.password === "string";

      if (!hasUsername && !hasPassword) {
        return false;
      }

      fillLoginForm({
        username: hasUsername ? message.username : undefined,
        password: hasPassword ? message.password : undefined
      });

      return false;
    }
  );
}
