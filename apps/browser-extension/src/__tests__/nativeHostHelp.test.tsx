import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { renderNativeHostHelp } from "../nativeHostHelp";

afterEach(() => {
  cleanup();
});

describe("resident native host recovery help", () => {
  it("explains that automatic resident activation already failed", () => {
    const error = Object.assign(new Error("resident unavailable"), {
      code: "resident_unavailable"
    });

    render(renderNativeHostHelp(error));

    expect(screen.getByText(/could not start VaultKern automatically/i)).toBeInTheDocument();
  });

  it("points Windows repairs at the protected native-host install", () => {
    const error = Object.assign(new Error("native host missing"), {
      code: "native_host_missing"
    });

    render(renderNativeHostHelp(error));

    expect(
      screen.getByText(/%ProgramFiles%\\VaultKern\\Browser Integration\\vaultkern-runtime\.exe/)
    ).toBeInTheDocument();
  });

  it.each(["resident_authentication_failed", "resident_connection_failed"])(
    "explains how to recover from %s",
    (code) => {
      const error = Object.assign(new Error("resident connection failed"), {
        code
      });

      render(renderNativeHostHelp(error));

      expect(
        screen.getByText("Repair the VaultKern resident connection")
      ).toBeInTheDocument();
      expect(
        screen.getByText(/restart the VaultKern Windows app/i)
      ).toBeInTheDocument();
      expect(
        screen.getByText(/update or repair the app and native host together/i)
      ).toBeInTheDocument();
    }
  );
});
