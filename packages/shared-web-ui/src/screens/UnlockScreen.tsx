import { useState } from "react";
import type { FormEvent } from "react";
import type { ReactNode } from "react";

import type { RuntimeClientLike } from "../App";
import { archiveTheme } from "../designTokens";

export function UnlockScreen({
  client,
  onUnlocked,
  renderRuntimeErrorHelp
}: {
  client: RuntimeClientLike;
  onUnlocked: (session: { unlocked: boolean; activeVaultId?: string | null }) => void;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [vaultPath, setVaultPath] = useState("");
  const [password, setPassword] = useState("");
  const [keyFilePath, setKeyFilePath] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [errorCause, setErrorCause] = useState<unknown>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setErrorCause(null);

    try {
      const vault = await client.openLocalVault(vaultPath);
      const session = await client.unlockVault(vault.vaultId, {
        password,
        keyFilePath
      });
      onUnlocked(session);
    } catch (submitError) {
      setErrorCause(submitError);
      setError(
        submitError instanceof Error ? submitError.message : "Failed to unlock vault"
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: archiveTheme.spacing.xl,
        background: `radial-gradient(circle at top left, ${archiveTheme.colors.page} 0%, ${archiveTheme.colors.pageShade} 65%, #dbc29f 100%)`
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{
          width: "min(520px, 100%)",
          display: "grid",
          gap: archiveTheme.spacing.lg,
          padding: archiveTheme.spacing.xl,
          border: `1px solid ${archiveTheme.colors.line}`,
          borderRadius: archiveTheme.radius.shell,
          background: "rgba(255, 251, 244, 0.94)",
          boxShadow: archiveTheme.shadow.shell
        }}
      >
        <div
          style={{
            display: "grid",
            gap: archiveTheme.spacing.xs
          }}
        >
          <span
            style={{
              color: archiveTheme.colors.textMuted,
              fontFamily: archiveTheme.font.mono,
              fontSize: "0.78rem",
              letterSpacing: "0.16em",
              textTransform: "uppercase"
            }}
          >
            Private Archive
          </span>
          <h1
            style={{
              margin: 0,
              color: archiveTheme.colors.text,
              fontFamily: archiveTheme.font.display,
              fontSize: "2.6rem",
              fontWeight: 600
            }}
          >
            Unlock your vault
          </h1>
          <p
            style={{
              margin: 0,
              color: archiveTheme.colors.textMuted,
              fontFamily: archiveTheme.font.body,
              lineHeight: 1.6
            }}
          >
            Open a local KDBX archive and return to the manager workspace.
          </p>
        </div>
        <div>
          <label
            style={{
              display: "grid",
              gap: archiveTheme.spacing.xs,
              fontFamily: archiveTheme.font.body
            }}
          >
            Vault Path
            <input
              name="vaultPath"
              type="text"
              value={vaultPath}
              onChange={(event) => setVaultPath(event.target.value)}
              style={unlockFieldStyle}
            />
          </label>
        </div>
        <div>
          <label
            style={{
              display: "grid",
              gap: archiveTheme.spacing.xs,
              fontFamily: archiveTheme.font.body
            }}
          >
            Master Password
            <input
              name="masterPassword"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              style={unlockFieldStyle}
            />
          </label>
        </div>
        <div>
          <label
            style={{
              display: "grid",
              gap: archiveTheme.spacing.xs,
              fontFamily: archiveTheme.font.body
            }}
          >
            Key File Path
            <input
              name="keyFilePath"
              type="text"
              value={keyFilePath}
              onChange={(event) => setKeyFilePath(event.target.value)}
              style={unlockFieldStyle}
            />
          </label>
        </div>
        <button type="submit" disabled={submitting} style={unlockButtonStyle}>
          Unlock Vault
        </button>
        {error ? (
          <div
            role="alert"
            style={{
              borderRadius: archiveTheme.radius.field,
              padding: archiveTheme.spacing.sm,
              background: "rgba(139, 61, 42, 0.10)",
              color: archiveTheme.colors.danger,
              fontFamily: archiveTheme.font.body
            }}
          >
            {error}
          </div>
        ) : null}
        {error && renderRuntimeErrorHelp ? renderRuntimeErrorHelp(errorCause) : null}
      </form>
    </div>
  );
}

const unlockFieldStyle = {
  width: "100%",
  borderRadius: archiveTheme.radius.field,
  border: `1px solid ${archiveTheme.colors.line}`,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.98rem",
  boxSizing: "border-box" as const
};

const unlockButtonStyle = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: archiveTheme.font.body,
  fontSize: "1rem",
  cursor: "pointer"
};
