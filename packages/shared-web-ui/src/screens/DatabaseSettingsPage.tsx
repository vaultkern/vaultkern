import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type {
  DatabaseEncryptionSettings,
  DatabaseKdfSettings,
  DatabaseSettings,
  DatabaseSettingsUpdate
} from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";
import { useText } from "../i18n";

type Draft = {
  name: string;
  description: string;
  defaultUsername: string;
  publicDisplayName: string;
  publicColor: string;
  publicIcon: string;
  historyMaxItems: string;
  historyMaxSizeMiB: string;
  recycleBinEnabled: boolean;
  compression: string;
  autosaveDelaySeconds: string;
  credentialAction: "unchanged" | "change" | "remove";
  newPassword: string;
  confirmPassword: string;
  cipher: string;
  kdfAlgorithm: string;
  transformRounds: string;
  argon2Iterations: string;
  argon2MemoryMiB: string;
  argon2Parallelism: string;
};

export function DatabaseSettingsPage({
  settings,
  loading,
  saving,
  error,
  onSave
}: {
  settings: DatabaseSettings | null;
  loading: boolean;
  saving: boolean;
  error: string | null;
  onSave: (update: DatabaseSettingsUpdate) => void;
}) {
  const text = useText();
  const [draft, setDraft] = useState<Draft>(() => createDraft(settings));

  useEffect(() => {
    if (settings) {
      setDraft(createDraft(settings));
    }
  }, [settings]);

  function submit(event: FormEvent) {
    event.preventDefault();

    if (draft.credentialAction === "change" && draft.newPassword !== draft.confirmPassword) {
      return;
    }

    const kdf: DatabaseKdfSettings =
      draft.kdfAlgorithm === "aes_kdbx4"
        ? {
            algorithm: "aes_kdbx4",
            transformRounds: parseOptionalInteger(draft.transformRounds) ?? 100000,
            iterations: null,
            memoryKib: null,
            parallelism: null
          }
        : {
            algorithm: "argon2id",
            transformRounds: null,
            iterations: parseOptionalInteger(draft.argon2Iterations) ?? 2,
            memoryKib: miBToBytesAsKiB(draft.argon2MemoryMiB) ?? 65536,
            parallelism: parseOptionalInteger(draft.argon2Parallelism) ?? 1
          };
    const encryption: DatabaseEncryptionSettings = {
      compression: draft.compression,
      cipher: draft.cipher,
      kdf
    };

    onSave({
      metadata: {
        name: draft.name,
        description: nullableText(draft.description),
        defaultUsername: nullableText(draft.defaultUsername)
      },
      publicMetadata: {
        displayName: nullableText(draft.publicDisplayName),
        color: nullableText(draft.publicColor),
        icon: nullableText(draft.publicIcon)
      },
      history: {
        maxItemsPerEntry: parseOptionalInteger(draft.historyMaxItems),
        maxTotalSizeBytes: miBToBytes(draft.historyMaxSizeMiB)
      },
      recycleBin: {
        enabled: draft.recycleBinEnabled
      },
      encryption,
      autosaveDelaySeconds: parseOptionalInteger(draft.autosaveDelaySeconds) ?? 0,
      credentials:
        draft.credentialAction === "change"
          ? { newPassword: draft.newPassword, removePassword: false }
          : draft.credentialAction === "remove"
            ? { newPassword: null, removePassword: true }
            : undefined
    });
  }

  if (loading) {
    return <div style={panelTextStyle}>{text("Loading database settings...")}</div>;
  }

  if (!settings) {
    return (
      <section style={pageStyle}>
        <div role="alert" style={panelTextStyle}>
          {error ?? text("Database settings are unavailable.")}
        </div>
      </section>
    );
  }

  return (
    <form onSubmit={submit} style={pageStyle}>
      <div style={headerStyle}>
        <div style={titleBlockStyle}>
          <span style={labelStyle}>{text("Database")}</span>
          <h1 style={pageTitleStyle}>{settings.metadata.name}</h1>
        </div>
        <button type="submit" disabled={saving} style={primaryButtonStyle}>
          {saving ? text("Saving...") : text("Save settings")}
        </button>
      </div>
      {error ? <div role="alert">{error}</div> : null}

      <section style={sectionStyle}>
        <h2 style={sectionTitleStyle}>{text("Database Metadata")}</h2>
        <Field label={text("Database Name")}>
          <input
            value={draft.name}
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
            style={inputStyle}
          />
        </Field>
        <Field label={text("Description")}>
          <textarea
            value={draft.description}
            onChange={(event) => setDraft({ ...draft, description: event.target.value })}
            style={{ ...inputStyle, minHeight: "76px", resize: "vertical" }}
          />
        </Field>
        <Field label={text("Default Username")}>
          <input
            value={draft.defaultUsername}
            onChange={(event) =>
              setDraft({ ...draft, defaultUsername: event.target.value })
            }
            style={inputStyle}
          />
        </Field>
      </section>

      <section style={sectionStyle}>
        <h2 style={sectionTitleStyle}>{text("Public Metadata")}</h2>
        <Field label={text("Public Display Name")}>
          <input
            value={draft.publicDisplayName}
            onChange={(event) =>
              setDraft({ ...draft, publicDisplayName: event.target.value })
            }
            style={inputStyle}
          />
        </Field>
        <Field label={text("Public Color")}>
          <input
            value={draft.publicColor}
            onChange={(event) => setDraft({ ...draft, publicColor: event.target.value })}
            style={inputStyle}
          />
        </Field>
        <Field label={text("Public Icon")}>
          <input
            value={draft.publicIcon}
            onChange={(event) => setDraft({ ...draft, publicIcon: event.target.value })}
            style={inputStyle}
          />
        </Field>
      </section>

      <section style={sectionStyle}>
        <h2 style={sectionTitleStyle}>{text("History")}</h2>
        <Field label={text("History Items Per Entry")}>
          <input
            inputMode="numeric"
            value={draft.historyMaxItems}
            onChange={(event) =>
              setDraft({ ...draft, historyMaxItems: event.target.value })
            }
            style={inputStyle}
          />
        </Field>
        <Field label={text("History Total Size MiB")}>
          <input
            inputMode="numeric"
            value={draft.historyMaxSizeMiB}
            onChange={(event) =>
              setDraft({ ...draft, historyMaxSizeMiB: event.target.value })
            }
            style={inputStyle}
          />
        </Field>
        <label style={checkboxStyle}>
          <input
            type="checkbox"
            checked={draft.recycleBinEnabled}
            onChange={(event) =>
              setDraft({ ...draft, recycleBinEnabled: event.target.checked })
            }
          />
          {text("Enable recycle bin")}
        </label>
      </section>

      <section style={sectionStyle}>
        <h2 style={sectionTitleStyle}>{text("Save And Encryption")}</h2>
        <Field label={text("Compression")}>
          <select
            value={draft.compression}
            onChange={(event) => setDraft({ ...draft, compression: event.target.value })}
            style={inputStyle}
          >
            <option value="gzip">GZip</option>
            <option value="none">None</option>
          </select>
        </Field>
        <Field label={text("Autosave Delay Seconds")}>
          <input
            inputMode="numeric"
            value={draft.autosaveDelaySeconds}
            onChange={(event) =>
              setDraft({ ...draft, autosaveDelaySeconds: event.target.value })
            }
            style={inputStyle}
          />
        </Field>
        <Field label={text("Cipher")}>
          <select
            value={draft.cipher}
            onChange={(event) => setDraft({ ...draft, cipher: event.target.value })}
            style={inputStyle}
          >
            <option value="aes256">AES-256</option>
            <option value="chacha20">ChaCha20</option>
            <option value="twofish">Twofish</option>
          </select>
        </Field>
        <Field label={text("Key Derivation Function")}>
          <select
            value={draft.kdfAlgorithm}
            onChange={(event) => setDraft({ ...draft, kdfAlgorithm: event.target.value })}
            style={inputStyle}
          >
            <option value="argon2id">Argon2id</option>
            <option value="aes_kdbx4">AES-KDF</option>
          </select>
        </Field>
        {draft.kdfAlgorithm === "aes_kdbx4" ? (
          <Field label={text("Transform Rounds")}>
            <input
              inputMode="numeric"
              value={draft.transformRounds}
              onChange={(event) =>
                setDraft({ ...draft, transformRounds: event.target.value })
              }
              style={inputStyle}
            />
          </Field>
        ) : (
          <>
            <Field label={text("Argon2 Iterations")}>
              <input
                inputMode="numeric"
                value={draft.argon2Iterations}
                onChange={(event) =>
                  setDraft({ ...draft, argon2Iterations: event.target.value })
                }
                style={inputStyle}
              />
            </Field>
            <Field label={text("Argon2 Memory MiB")}>
              <input
                inputMode="numeric"
                value={draft.argon2MemoryMiB}
                onChange={(event) =>
                  setDraft({ ...draft, argon2MemoryMiB: event.target.value })
                }
                style={inputStyle}
              />
            </Field>
            <Field label={text("Argon2 Parallelism")}>
              <input
                inputMode="numeric"
                value={draft.argon2Parallelism}
                onChange={(event) =>
                  setDraft({ ...draft, argon2Parallelism: event.target.value })
                }
                style={inputStyle}
              />
            </Field>
          </>
        )}
      </section>

      <section style={sectionStyle}>
        <h2 style={sectionTitleStyle}>{text("Credentials")}</h2>
        <div style={credentialButtonRowStyle}>
          <button
            type="button"
            onClick={() =>
              setDraft({
                ...draft,
                credentialAction: "change",
                newPassword: "",
                confirmPassword: ""
              })
            }
            style={draft.credentialAction === "change" ? primaryButtonStyle : backButtonStyle}
          >
            {settings.hasPassword ? text("Change password") : text("Add password")}
          </button>
          {settings.hasPassword ? (
            <button
              type="button"
              onClick={() =>
                setDraft({
                  ...draft,
                  credentialAction: "remove",
                  newPassword: "",
                  confirmPassword: ""
                })
              }
              style={draft.credentialAction === "remove" ? dangerButtonStyle : backButtonStyle}
            >
              {text("Remove password")}
            </button>
          ) : null}
        </div>
        {draft.credentialAction === "change" ? (
          <>
            <Field label={text("New Master Password")}>
              <input
                type="password"
                value={draft.newPassword}
                onChange={(event) =>
                  setDraft({ ...draft, newPassword: event.target.value })
                }
                style={inputStyle}
              />
            </Field>
            <Field label={text("Confirm New Master Password")}>
              <input
                type="password"
                value={draft.confirmPassword}
                onChange={(event) =>
                  setDraft({ ...draft, confirmPassword: event.target.value })
                }
                style={inputStyle}
              />
            </Field>
            {draft.newPassword !== draft.confirmPassword ? (
              <div role="alert" style={inlineErrorStyle}>
                {text("Password confirmation does not match.")}
              </div>
            ) : null}
          </>
        ) : null}
        {draft.credentialAction === "remove" ? (
          <div style={panelTextStyle}>
            {text("Saving will remove the current database password.")}
          </div>
        ) : null}
      </section>
    </form>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={fieldStyle}>
      <span style={labelStyle}>{label}</span>
      {children}
    </label>
  );
}

function createDraft(settings: DatabaseSettings | null): Draft {
  return {
    name: settings?.metadata.name ?? "",
    description: settings?.metadata.description ?? "",
    defaultUsername: settings?.metadata.defaultUsername ?? "",
    publicDisplayName: settings?.publicMetadata.displayName ?? "",
    publicColor: settings?.publicMetadata.color ?? "",
    publicIcon: settings?.publicMetadata.icon ?? "",
    historyMaxItems: optionalNumber(settings?.history.maxItemsPerEntry),
    historyMaxSizeMiB: optionalMiB(settings?.history.maxTotalSizeBytes),
    recycleBinEnabled: settings?.recycleBin.enabled ?? true,
    compression: settings?.encryption.compression ?? "gzip",
    autosaveDelaySeconds: optionalNumber(settings?.autosaveDelaySeconds),
    credentialAction: "unchanged",
    newPassword: "",
    confirmPassword: "",
    cipher: settings?.encryption.cipher ?? "aes256",
    kdfAlgorithm: settings?.encryption.kdf.algorithm ?? "argon2id",
    transformRounds: optionalNumber(settings?.encryption.kdf.transformRounds),
    argon2Iterations: optionalNumber(settings?.encryption.kdf.iterations),
    argon2MemoryMiB: optionalKiBAsMiB(settings?.encryption.kdf.memoryKib),
    argon2Parallelism: optionalNumber(settings?.encryption.kdf.parallelism)
  };
}

function optionalNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? "" : String(value);
}

function nullableText(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function parseOptionalInteger(value: string): number | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function optionalMiB(value: number | null | undefined): string {
  return value === null || value === undefined ? "" : String(Math.round(value / 1048576));
}

function optionalKiBAsMiB(value: number | null | undefined): string {
  return value === null || value === undefined ? "" : String(Math.round(value / 1024));
}

function miBToBytes(value: string): number | null {
  const parsed = parseOptionalInteger(value);
  return parsed === null ? null : parsed * 1048576;
}

function miBToBytesAsKiB(value: string): number | null {
  const parsed = parseOptionalInteger(value);
  return parsed === null ? null : parsed * 1024;
}

const pageStyle = {
  display: "grid",
  gap: archiveTheme.spacing.lg,
  alignContent: "start"
};

const headerStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  alignItems: "center",
  justifyContent: "space-between",
  gap: archiveTheme.spacing.sm
};

const titleBlockStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  minWidth: 0,
  flex: "1 1 260px"
};

const pageTitleStyle = {
  margin: 0,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.display,
  fontSize: "1.7rem",
  fontWeight: 600,
  overflowWrap: "anywhere" as const
};

const sectionStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: archiveTheme.spacing.md,
  paddingTop: archiveTheme.spacing.sm,
  borderTop: `1px solid ${archiveTheme.colors.line}`
};

const sectionTitleStyle = {
  gridColumn: "1 / -1",
  margin: 0,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.display,
  fontSize: "1.12rem",
  fontWeight: 600
};

const fieldStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  minWidth: 0
};

const labelStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.72rem",
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const
};

const inputStyle = {
  width: "100%",
  boxSizing: "border-box" as const,
  borderRadius: archiveTheme.radius.field,
  border: `1px solid ${archiveTheme.colors.line}`,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.95rem"
};

const checkboxStyle = {
  display: "flex",
  gap: archiveTheme.spacing.sm,
  alignItems: "center",
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const backButtonStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const primaryButtonStyle = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const dangerButtonStyle = {
  border: `1px solid ${archiveTheme.colors.danger}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: "rgba(139, 61, 42, 0.12)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const panelTextStyle = {
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const credentialButtonRowStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  gap: archiveTheme.spacing.sm,
  alignItems: "center"
};

const inlineErrorStyle = {
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  alignSelf: "end"
};
