import { fillLoginForm as fillLoginFormWithAuthorization } from "../../contentScript";
import { createManualFillCapability, type FillCapability } from "../fillAuthorization";

export function fillLoginFormWithTestAuthorization(
  payload: Parameters<typeof fillLoginFormWithAuthorization>[0],
  authorization?: FillCapability | unknown
) {
  return fillLoginFormWithAuthorization(
    payload,
    authorization ??
      createManualFillCapability({
        targetUrl: window.location.href,
        entryId: "test-entry"
      })
  );
}
