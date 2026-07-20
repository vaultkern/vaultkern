import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

import type {
  EntryAttachment,
  EntryCustomField,
  EntryDetail,
  EntryHistoryDetail,
  EntryHistoryItem,
  EntryPasskey
} from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";
import { useText } from "../i18n";
import {
  DEFAULT_PASSWORD_GENERATOR_OPTIONS,
  generatePassword
} from "../passwordGenerator";
import type { PasswordGeneratorOptions } from "../passwordGenerator";
import type { EntryEditorMode } from "../types";

type DraftField = "title" | "username" | "password" | "url" | "notes" | "totpUri";

type EntryDraftLike = {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpUri: string | null;
  customFields: EntryCustomField[];
};

export function EntryEditor({
  entry,
  mode,
  draft,
  dirty,
  busy,
  pendingSave,
  historyItems,
  historyDetail,
  historyError,
  onStartEdit,
  onChangeDraft,
  onChangeCustomField,
  onAddCustomField,
  onDeleteCustomField,
  onDownloadAttachment,
  onAddAttachment,
  onRenameAttachment,
  onReplaceAttachment,
  onDeleteAttachment,
  onSelectHistoryItem,
  onSetPasskey,
  onClearPasskey,
  onRetrySave,
  onSave,
  onCancel,
  onDelete
}: {
  entry: EntryDetail | null;
  mode: EntryEditorMode;
  draft: EntryDraftLike | null;
  dirty: boolean;
  busy?: boolean;
  pendingSave?: boolean;
  historyItems?: EntryHistoryItem[];
  historyDetail?: EntryHistoryDetail | null;
  historyError?: string | null;
  onStartEdit?: () => void;
  onChangeDraft: (field: DraftField, value: string) => void;
  onChangeCustomField: (
    index: number,
    field: keyof EntryCustomField,
    value: string | boolean
  ) => void;
  onAddCustomField: () => void;
  onDeleteCustomField: (index: number) => void;
  onDownloadAttachment?: (name: string) => void;
  onAddAttachment?: (file: File, protectInMemory: boolean) => void;
  onRenameAttachment?: (
    oldName: string,
    newName: string,
    protectInMemory: boolean
  ) => void;
  onReplaceAttachment?: (name: string, file: File) => void;
  onDeleteAttachment?: (name: string) => void;
  onSelectHistoryItem?: (historyIndex: number) => void;
  onSetPasskey?: (passkey: EntryPasskey) => void;
  onClearPasskey?: () => void;
  onRetrySave?: () => void;
  onSave: () => void;
  onCancel: () => void;
  onDelete?: () => void;
}) {
  const text = useText();
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [generatorOptions, setGeneratorOptions] = useState<PasswordGeneratorOptions>(
    DEFAULT_PASSWORD_GENERATOR_OPTIONS
  );
  const [generatedPassword, setGeneratedPassword] = useState("");
  const editable = mode !== "view";
  const values = editable && draft ? draft : entry;

  useEffect(() => {
    setShowPassword(false);
    setShowGenerator(false);
  }, [entry?.id, mode]);

  function regeneratePassword(nextOptions = generatorOptions) {
    setGeneratedPassword(generatePassword(nextOptions));
  }

  function updateGeneratorOptions(nextOptions: PasswordGeneratorOptions) {
    setGeneratorOptions(nextOptions);
    regeneratePassword(nextOptions);
  }

  if (!values) {
    return (
      <div
        style={{
          color: archiveTheme.colors.textMuted,
          fontFamily: archiveTheme.font.body
        }}
      >
        {text("Select an entry to view details.")}
      </div>
    );
  }

  const title = mode === "create-pending" ? text("Create Entry") : values.title;

  return (
    <div
      style={{
        display: "grid",
        gap: archiveTheme.spacing.md
      }}
    >
      <style>
        {`
          @keyframes vaultkern-save-spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}
      </style>
      <div
        style={{
          display: "grid",
          gap: archiveTheme.spacing.sm
        }}
      >
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "space-between",
            gap: archiveTheme.spacing.sm,
            alignItems: "start"
          }}
        >
          <div
            style={{
              display: "grid",
              gap: archiveTheme.spacing.xs
            }}
          >
            <div
              style={{
                color: archiveTheme.colors.textMuted,
                fontFamily: archiveTheme.font.mono,
                fontSize: "0.74rem",
                letterSpacing: "0.16em",
                textTransform: "uppercase"
              }}
            >
              {mode === "create-pending" ? text("New Entry") : text("Entry Detail")}
            </div>
            <h2
              style={{
                margin: 0,
                color: archiveTheme.colors.text,
                fontFamily: archiveTheme.font.display,
                fontSize: "1.9rem",
                fontWeight: 600
              }}
            >
              {title || text("Untitled Entry")}
            </h2>
            {mode === "view" && typeof entry?.modifiedAt === "number" ? (
              <div style={metadataTextStyle}>
                {text("Modified At")}: {formatUnixTimestamp(entry.modifiedAt)}
              </div>
            ) : null}
          </div>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: archiveTheme.spacing.sm,
              justifyContent: "flex-end"
            }}
          >
            {mode === "view" && entry && onStartEdit ? (
              <button
                type="button"
                onClick={onStartEdit}
                disabled={busy || pendingSave}
                style={secondaryActionStyle}
              >
                {text("Edit")}
              </button>
            ) : null}
            {editable ? (
              <>
                <button
                  type="button"
                  onClick={onCancel}
                  disabled={busy}
                  style={secondaryActionStyle}
                >
                  {text("Cancel")}
                </button>
                <button
                  type="button"
                  onClick={onSave}
                  disabled={busy || !dirty}
                  aria-busy={busy ? "true" : undefined}
                  style={{
                    ...primaryActionStyle,
                    opacity: busy || !dirty ? 0.6 : 1,
                    cursor: busy || !dirty ? "default" : "pointer"
                  }}
                >
                  <span style={saveButtonContentStyle}>
                    {busy ? (
                      <span
                        aria-hidden="true"
                        data-testid="entry-save-spinner"
                        style={saveSpinnerStyle}
                      />
                    ) : null}
                    {busy ? text("Saving...") : text("Save changes")}
                  </span>
                </button>
              </>
            ) : null}
            {mode === "view" && entry && onDelete ? (
              <button
                type="button"
                onClick={onDelete}
                disabled={busy || pendingSave}
                style={dangerActionStyle}
              >
                {text("Delete Entry")}
              </button>
            ) : null}
          </div>
        </div>
      </div>
      <Field
        label={text("Title")}
        value={values.title}
        editable={editable}
        onChange={(value) => onChangeDraft("title", value)}
      />
      <Field
        label={text("Username")}
        value={values.username}
        editable={editable}
        onChange={(value) => onChangeDraft("username", value)}
      />
      <label
        style={{
          display: "grid",
          gap: archiveTheme.spacing.xs,
          fontFamily: archiveTheme.font.body
        }}
      >
        {text("Password")}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: editable ? "minmax(0, 1fr) auto auto" : "minmax(0, 1fr) auto",
            gap: archiveTheme.spacing.sm,
            alignItems: "center"
          }}
        >
          <input
            type={showPassword ? "text" : "password"}
            readOnly={!editable}
            value={values.password}
            onChange={(event) => onChangeDraft("password", event.target.value)}
            style={fieldStyle}
          />
          <button
            type="button"
            onClick={() => setShowPassword((current) => !current)}
            style={secondaryActionStyle}
          >
            {showPassword ? text("Hide password") : text("Show password")}
          </button>
          {editable ? (
            <button
              type="button"
              onClick={() => {
                setShowGenerator((current) => !current);
                if (!showGenerator) {
                  regeneratePassword();
                }
              }}
              style={secondaryActionStyle}
            >
              {text("Generate")}
            </button>
          ) : null}
        </div>
      </label>
      {editable && showGenerator ? (
        <PasswordGeneratorPanel
          options={generatorOptions}
          generatedPassword={generatedPassword}
          text={text}
          onChangeOptions={updateGeneratorOptions}
          onRegenerate={() => regeneratePassword()}
          onUsePassword={() => {
            onChangeDraft("password", generatedPassword);
            setShowGenerator(false);
          }}
        />
      ) : null}
      <Field
        label={text("URL")}
        value={values.url}
        editable={editable}
        onChange={(value) => onChangeDraft("url", value)}
      />
      <label
        style={{
          display: "grid",
          gap: archiveTheme.spacing.xs,
          fontFamily: archiveTheme.font.body
        }}
      >
        {text("Notes")}
        <textarea
          readOnly={!editable}
          value={values.notes}
          onChange={(event) => onChangeDraft("notes", event.target.value)}
          style={notesStyle}
        />
      </label>
      {editable ? (
        <Field
          label={text("TOTP URI")}
          value={values.totpUri ?? ""}
          editable
          onChange={(value) => onChangeDraft("totpUri", value)}
        />
      ) : null}
      {mode === "view" && entry ? (
        <PasskeySection
          entry={entry}
          text={text}
          busy={busy}
          pendingSave={pendingSave}
          onSetPasskey={onSetPasskey}
          onClearPasskey={onClearPasskey}
          onRetrySave={onRetrySave}
        />
      ) : null}
      {mode === "view" && entry ? (
        <EntryDetailExtras
          entry={entry}
          text={text}
          onDownloadAttachment={onDownloadAttachment}
        />
      ) : null}
      {editable && draft ? (
        <EditableCustomFields
          fields={draft.customFields}
          text={text}
          onChange={onChangeCustomField}
          onAdd={onAddCustomField}
          onDelete={onDeleteCustomField}
        />
      ) : null}
      {editable && entry ? (
        <EditableAttachments
          attachments={entry.attachments ?? []}
          text={text}
          onAdd={onAddAttachment}
          onRename={onRenameAttachment}
          onReplace={onReplaceAttachment}
          onDelete={onDeleteAttachment}
        />
      ) : null}
      {mode === "view" && entry ? (
        <EntryHistorySection
          items={historyItems ?? []}
          detail={historyDetail ?? null}
          error={historyError ?? null}
          text={text}
          onSelect={onSelectHistoryItem}
        />
      ) : null}
    </div>
  );
}

function PasswordGeneratorPanel({
  options,
  generatedPassword,
  text,
  onChangeOptions,
  onRegenerate,
  onUsePassword
}: {
  options: PasswordGeneratorOptions;
  generatedPassword: string;
  text: ReturnType<typeof useText>;
  onChangeOptions: (options: PasswordGeneratorOptions) => void;
  onRegenerate: () => void;
  onUsePassword: () => void;
}) {
  return (
    <section aria-label={text("Password Generator")} style={generatorPanelStyle}>
      <div style={sectionHeaderStyle}>
        <h3 style={sectionTitleStyle}>{text("Password Generator")}</h3>
        <div style={inlineActionsStyle}>
          <button type="button" onClick={onRegenerate} style={secondaryActionStyle}>
            {text("Regenerate")}
          </button>
          <button type="button" onClick={onUsePassword} style={primaryActionStyle}>
            {text("Use password")}
          </button>
        </div>
      </div>
      <label style={fieldLabelStyle}>
        {text("Generated password")}
        <input readOnly value={generatedPassword} style={fieldStyle} />
      </label>
      <div style={generatorControlsStyle}>
        <label style={fieldLabelStyle}>
          {text("Length")}
          <input
            type="number"
            min={4}
            max={128}
            value={options.length}
            onChange={(event) =>
              onChangeOptions({
                ...options,
                length: Number.parseInt(event.target.value, 10) || 1
              })
            }
            style={fieldStyle}
          />
        </label>
        <GeneratorCheckbox
          label={text("Uppercase")}
          checked={options.includeUppercase}
          onChange={(checked) =>
            onChangeOptions({ ...options, includeUppercase: checked })
          }
        />
        <GeneratorCheckbox
          label={text("Lowercase")}
          checked={options.includeLowercase}
          onChange={(checked) =>
            onChangeOptions({ ...options, includeLowercase: checked })
          }
        />
        <GeneratorCheckbox
          label={text("Numbers")}
          checked={options.includeNumbers}
          onChange={(checked) => onChangeOptions({ ...options, includeNumbers: checked })}
        />
        <GeneratorCheckbox
          label={text("Symbols")}
          checked={options.includeSymbols}
          onChange={(checked) => onChangeOptions({ ...options, includeSymbols: checked })}
        />
      </div>
    </section>
  );
}

function GeneratorCheckbox({
  label,
  checked,
  onChange
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label style={checkboxLabelStyle}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      {label}
    </label>
  );
}

function EditableCustomFields({
  fields,
  text,
  onChange,
  onAdd,
  onDelete
}: {
  fields: EntryCustomField[];
  text: ReturnType<typeof useText>;
  onChange: (
    index: number,
    field: keyof EntryCustomField,
    value: string | boolean
  ) => void;
  onAdd: () => void;
  onDelete: (index: number) => void;
}) {
  return (
    <section aria-label={text("Additional Properties")} style={sectionStyle}>
      <div style={sectionHeaderStyle}>
        <h3 style={sectionTitleStyle}>{text("Additional Properties")}</h3>
        <button type="button" onClick={onAdd} style={secondaryActionStyle}>
          {text("Add property")}
        </button>
      </div>
      {fields.length === 0 ? (
        <div style={detailValueStyle}>{text("No additional properties.")}</div>
      ) : (
        <div style={editableFieldListStyle}>
          {fields.map((field, index) => {
            const keyLabel = field.key.trim() || `Property ${index + 1}`;
            return (
              <div key={index} style={editableFieldRowStyle}>
                <label style={inlineFieldStyle}>
                  {text("Key")}
                  <input
                    aria-label={`Property ${index + 1} key`}
                    type="text"
                    value={field.key}
                    onChange={(event) => onChange(index, "key", event.target.value)}
                    style={fieldStyle}
                  />
                </label>
                <label style={inlineFieldStyle}>
                  {text("Value")}
                  <input
                    aria-label={`${keyLabel} value`}
                    type={field.protected ? "password" : "text"}
                    value={field.value}
                    onChange={(event) => onChange(index, "value", event.target.value)}
                    style={fieldStyle}
                  />
                </label>
                <label style={checkboxFieldStyle}>
                  <input
                    type="checkbox"
                    checked={field.protected}
                    onChange={(event) =>
                      onChange(index, "protected", event.target.checked)
                    }
                  />
                  {text("Protected")}
                </label>
                <button
                  type="button"
                  aria-label={`Remove ${keyLabel}`}
                  onClick={() => onDelete(index)}
                  style={dangerSmallButtonStyle}
                >
                  {text("Remove")}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function EditableAttachments({
  attachments,
  text,
  onAdd,
  onRename,
  onReplace,
  onDelete
}: {
  attachments: EntryAttachment[];
  text: ReturnType<typeof useText>;
  onAdd?: (file: File, protectInMemory: boolean) => void;
  onRename?: (oldName: string, newName: string, protectInMemory: boolean) => void;
  onReplace?: (name: string, file: File) => void;
  onDelete?: (name: string) => void;
}) {
  const [protectNewAttachment, setProtectNewAttachment] = useState(false);

  return (
    <section aria-label={text("Attachments")} style={sectionStyle}>
      <div style={sectionHeaderStyle}>
        <h3 style={sectionTitleStyle}>{text("Attachments")}</h3>
        <label style={checkboxFieldStyle}>
          <input
            type="checkbox"
            checked={protectNewAttachment}
            onChange={(event) => setProtectNewAttachment(event.target.checked)}
          />
          {text("Protect new attachment")}
        </label>
        <label style={secondaryActionStyle}>
          {text("Add attachment")}
          <input
            aria-label={text("Add attachment file")}
            type="file"
            style={hiddenFileInputStyle}
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) {
                onAdd?.(file, protectNewAttachment);
              }
              event.currentTarget.value = "";
            }}
          />
        </label>
      </div>
      {attachments.length === 0 ? (
        <div style={detailValueStyle}>{text("No attachments.")}</div>
      ) : (
        <div style={editableFieldListStyle}>
          {attachments.map((attachment) => (
            <div key={attachment.name} style={attachmentEditRowStyle}>
              <label style={inlineFieldStyle}>
                {text("Name")}
                <input
                  aria-label={`Rename ${attachment.name}`}
                  type="text"
                  defaultValue={attachment.name}
                  onBlur={(event) => {
                    const newName = event.target.value.trim();
                    if (newName && newName !== attachment.name) {
                      onRename?.(
                        attachment.name,
                        newName,
                        attachment.protectInMemory
                      );
                    }
                  }}
                  style={fieldStyle}
                />
              </label>
              <div style={detailValueStyle}>{formatBytes(attachment.size)}</div>
              <label style={checkboxFieldStyle}>
                <input
                  aria-label={`Protect ${attachment.name}`}
                  type="checkbox"
                  checked={attachment.protectInMemory}
                  onChange={(event) =>
                    onRename?.(
                      attachment.name,
                      attachment.name,
                      event.target.checked
                    )
                  }
                />
                {text("Protected")}
              </label>
              <label style={secondaryActionStyle}>
                {text("Replace")}
                <input
                  aria-label={`Replace ${attachment.name}`}
                  type="file"
                  style={hiddenFileInputStyle}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) {
                      onReplace?.(attachment.name, file);
                    }
                    event.currentTarget.value = "";
                  }}
                />
              </label>
              <button
                type="button"
                aria-label={`Remove ${attachment.name}`}
                onClick={() => onDelete?.(attachment.name)}
                style={dangerSmallButtonStyle}
              >
                {text("Remove")}
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function PasskeySection({
  entry,
  text,
  busy,
  pendingSave,
  onSetPasskey,
  onClearPasskey,
  onRetrySave
}: {
  entry: EntryDetail;
  text: ReturnType<typeof useText>;
  busy?: boolean;
  pendingSave?: boolean;
  onSetPasskey?: (passkey: EntryPasskey) => void;
  onClearPasskey?: () => void;
  onRetrySave?: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<EntryPasskey>(() =>
    entry.passkey ?? emptyPasskey()
  );
  const [revealedPasskeyFields, setRevealedPasskeyFields] = useState<Set<string>>(
    () => new Set()
  );
  const [revealedDraftFields, setRevealedDraftFields] = useState<Set<string>>(
    () => new Set()
  );

  useEffect(() => {
    setEditing(false);
    setDraft(entry.passkey ?? emptyPasskey());
    setRevealedPasskeyFields(new Set());
    setRevealedDraftFields(new Set());
  }, [entry.id, entry.passkey]);

  function updateDraft(field: keyof EntryPasskey, value: string | boolean) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function toggleRevealedField(
    setter: Dispatch<SetStateAction<Set<string>>>,
    field: string
  ) {
    setter((current) => {
      const next = new Set(current);
      if (next.has(field)) {
        next.delete(field);
      } else {
        next.add(field);
      }
      return next;
    });
  }

  function sensitiveValue(value: string | null | undefined, revealed: boolean) {
    if (!value) {
      return "-";
    }
    return revealed ? value : "************";
  }

  function showHideLabel(revealed: boolean, label: string) {
    return `${showHideAction(revealed)} ${label}`;
  }

  function showHideAction(revealed: boolean) {
    return revealed ? text("Hide") : text("Show");
  }

  function renderSensitivePasskeyRow(
    label: string,
    field: string,
    value: string | null | undefined
  ) {
    const revealed = revealedPasskeyFields.has(field);
    return (
      <div style={detailRowStyle}>
        <div style={detailKeyStyle}>{label}</div>
        <div style={detailValueStyle}>{sensitiveValue(value, revealed)}</div>
        {value ? (
          <button
            type="button"
            aria-label={showHideLabel(revealed, label)}
            onClick={() =>
              toggleRevealedField(setRevealedPasskeyFields, field)
            }
            style={protectedToggleStyle}
          >
            {showHideAction(revealed)}
          </button>
        ) : null}
      </div>
    );
  }

  function renderSensitiveDraftInput(
    label: string,
    field: "credentialId" | "generatedUserId" | "userHandle" | "privateKeyPem",
    value: string,
    updateField: keyof EntryPasskey
  ) {
    const revealed = revealedDraftFields.has(field);
    const control =
      field === "privateKeyPem" ? (
        <textarea
          aria-label={label}
          value={value}
          onChange={(event) => updateDraft(updateField, event.target.value)}
          spellCheck={false}
          style={
            revealed
              ? privateKeyPemDraftStyle
              : concealedPrivateKeyPemDraftStyle
          }
        />
      ) : (
        <input
          aria-label={label}
          type={revealed ? "text" : "password"}
          value={value}
          onChange={(event) => updateDraft(updateField, event.target.value)}
          style={fieldStyle}
        />
      );

    return (
      <div style={sensitiveDraftFieldStyle}>
        <label style={fieldLabelStyle}>
          {label}
          {control}
        </label>
        <button
          type="button"
          aria-label={showHideLabel(revealed, label)}
          onClick={() => toggleRevealedField(setRevealedDraftFields, field)}
          style={protectedToggleStyle}
        >
          {showHideAction(revealed)}
        </button>
      </div>
    );
  }

  function normalizedDraft(): EntryPasskey {
    return {
      ...draft,
      username: draft.username.trim(),
      credentialId: draft.credentialId.trim(),
      generatedUserId: emptyStringAsNull(draft.generatedUserId),
      privateKeyPem: draft.privateKeyPem.trim(),
      relyingParty: draft.relyingParty.trim(),
      userHandle: emptyStringAsNull(draft.userHandle)
    };
  }

  const passkey = entry.passkey;

  function draftIsValid() {
    return (
      draft.credentialId.trim() !== "" &&
      draft.relyingParty.trim() !== "" &&
      privateKeyPemLooksValid(draft.privateKeyPem, passkey?.privateKeyPem)
    );
  }

  return (
    <section aria-label={text("Passkey")} style={sectionStyle}>
      <div style={sectionHeaderStyle}>
        <h3 style={sectionTitleStyle}>{text("Passkey")}</h3>
        <div style={inlineActionsStyle}>
          {pendingSave ? (
            <button
              type="button"
              onClick={() => onRetrySave?.()}
              disabled={busy}
              style={primaryActionStyle}
            >
              {text("Retry save")}
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={() => {
                  setDraft(passkey ?? emptyPasskey());
                  setRevealedDraftFields(new Set());
                  setEditing((current) => !current);
                }}
                disabled={busy}
                style={secondaryActionStyle}
              >
                {passkey ? text("Edit passkey") : text("Add passkey")}
              </button>
              {passkey ? (
                <button
                  type="button"
                  onClick={() => onClearPasskey?.()}
                  disabled={busy}
                  style={dangerSmallButtonStyle}
                >
                  {text("Clear passkey")}
                </button>
              ) : null}
            </>
          )}
        </div>
      </div>
      {passkey ? (
        <div style={detailListStyle}>
          <div style={detailRowStyle}>
            <div style={detailKeyStyle}>{text("Relying Party")}</div>
            <div style={detailValueStyle}>{passkey.relyingParty}</div>
          </div>
          <div style={detailRowStyle}>
            <div style={detailKeyStyle}>{text("Passkey Username")}</div>
            <div style={detailValueStyle}>{passkey.username}</div>
          </div>
          {renderSensitivePasskeyRow(
            text("Credential ID"),
            "credentialId",
            passkey.credentialId
          )}
          {renderSensitivePasskeyRow(
            text("Generated User ID"),
            "generatedUserId",
            passkey.generatedUserId
          )}
          {renderSensitivePasskeyRow(
            text("User Handle"),
            "userHandle",
            passkey.userHandle
          )}
          {renderSensitivePasskeyRow(
            text("Private Key PEM"),
            "privateKeyPem",
            passkey.privateKeyPem
          )}
          <div style={detailRowStyle}>
            <div style={detailKeyStyle}>{text("Backup eligible")}</div>
            <div style={detailValueStyle}>{passkey.backupEligible ? "true" : "false"}</div>
          </div>
          <div style={detailRowStyle}>
            <div style={detailKeyStyle}>{text("Backup state")}</div>
            <div style={detailValueStyle}>{passkey.backupState ? "true" : "false"}</div>
          </div>
        </div>
      ) : (
        <div style={detailValueStyle}>{text("No passkey.")}</div>
      )}
      {editing ? (
        <div style={editableFieldListStyle}>
          <label style={fieldLabelStyle}>
            {text("Passkey Username")}
            <input
              aria-label={text("Passkey Username")}
              value={draft.username}
              onChange={(event) => updateDraft("username", event.target.value)}
              style={fieldStyle}
            />
          </label>
          <label style={fieldLabelStyle}>
            {text("Relying Party")}
            <input
              aria-label={text("Relying Party")}
              value={draft.relyingParty}
              onChange={(event) => updateDraft("relyingParty", event.target.value)}
              style={fieldStyle}
            />
          </label>
          {renderSensitiveDraftInput(
            text("Credential ID"),
            "credentialId",
            draft.credentialId,
            "credentialId"
          )}
          {renderSensitiveDraftInput(
            text("Generated User ID"),
            "generatedUserId",
            draft.generatedUserId ?? "",
            "generatedUserId"
          )}
          {renderSensitiveDraftInput(
            text("User Handle"),
            "userHandle",
            draft.userHandle ?? "",
            "userHandle"
          )}
          {renderSensitiveDraftInput(
            text("Private Key PEM"),
            "privateKeyPem",
            draft.privateKeyPem,
            "privateKeyPem"
          )}
          <div style={inlineActionsStyle}>
            <label style={checkboxFieldStyle}>
              <input
                aria-label={text("Backup eligible")}
                type="checkbox"
                checked={draft.backupEligible}
                onChange={(event) => updateDraft("backupEligible", event.target.checked)}
              />
              {text("Backup eligible")}
            </label>
            <label style={checkboxFieldStyle}>
              <input
                aria-label={text("Backup state")}
                type="checkbox"
                checked={draft.backupState}
                onChange={(event) => updateDraft("backupState", event.target.checked)}
              />
              {text("Backup state")}
            </label>
          </div>
          <div style={inlineActionsStyle}>
            <button
              type="button"
              disabled={busy || !draftIsValid()}
              onClick={() => {
                onSetPasskey?.(normalizedDraft());
                setEditing(false);
                setRevealedPasskeyFields(new Set());
                setRevealedDraftFields(new Set());
              }}
              style={primaryActionStyle}
            >
              {text("Save passkey")}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setDraft(passkey ?? emptyPasskey());
                setEditing(false);
              }}
              style={secondaryActionStyle}
            >
              {text("Cancel")}
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function emptyPasskey(): EntryPasskey {
  return {
    username: "",
    credentialId: "",
    generatedUserId: null,
    privateKeyPem: "",
    relyingParty: "",
    userHandle: null,
    backupEligible: false,
    backupState: false
  };
}

function privateKeyPemLooksValid(value: string, existingValue?: string) {
  const trimmed = value.trim();
  if (
    existingValue !== undefined &&
    trimmed === existingValue.trim() &&
    privateKeyPemHasMatchingEnvelope(trimmed)
  ) {
    return true;
  }
  return /^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----$/u.test(
    trimmed
  );
}

function privateKeyPemHasMatchingEnvelope(value: string) {
  const match = value.match(
    /^-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]+-----END \1-----$/u
  );
  return Boolean(match);
}

function emptyStringAsNull(value: string | null): string | null {
  const trimmed = value?.trim() ?? "";
  return trimmed ? trimmed : null;
}

function EntryDetailExtras({
  entry,
  text,
  onDownloadAttachment
}: {
  entry: EntryDetail;
  text: ReturnType<typeof useText>;
  onDownloadAttachment?: (name: string) => void;
}) {
  const [revealedFields, setRevealedFields] = useState<Set<string>>(() => new Set());
  const customFields = entry.customFields ?? [];
  const attachments = entry.attachments ?? [];

  useEffect(() => {
    setRevealedFields(new Set());
  }, [entry.id]);

  if (customFields.length === 0 && attachments.length === 0) {
    return null;
  }

  return (
    <div
      style={{
        display: "grid",
        gap: archiveTheme.spacing.md,
        borderTop: `1px solid ${archiveTheme.colors.line}`,
        paddingTop: archiveTheme.spacing.md
      }}
    >
      {customFields.length > 0 ? (
        <section aria-label={text("Additional Properties")} style={sectionStyle}>
          <h3 style={sectionTitleStyle}>{text("Additional Properties")}</h3>
          <div style={detailListStyle}>
            {customFields.map((field) => {
              const revealed = revealedFields.has(field.key);
              return (
                <div key={field.key} style={detailRowStyle}>
                  <div style={detailKeyStyle}>{field.key}</div>
                  <div style={detailValueStyle}>
                    {field.protected && !revealed ? "************" : field.value}
                  </div>
                  {field.protected ? (
                    <button
                      type="button"
                      aria-label={`${revealed ? text("Hide") : text("Show")} ${field.key}`}
                      onClick={() => {
                        setRevealedFields((current) => {
                          const next = new Set(current);
                          if (next.has(field.key)) {
                            next.delete(field.key);
                          } else {
                            next.add(field.key);
                          }
                          return next;
                        });
                      }}
                      style={protectedToggleStyle}
                    >
                      {revealed ? text("Hide") : text("Show")}
                    </button>
                  ) : null}
                </div>
              );
            })}
          </div>
        </section>
      ) : null}
      {attachments.length > 0 ? (
        <section aria-label={text("Attachments")} style={sectionStyle}>
          <h3 style={sectionTitleStyle}>{text("Attachments")}</h3>
          <div style={detailListStyle}>
            {attachments.map((attachment) => (
              <div key={attachment.name} style={detailRowStyle}>
                <div style={detailKeyStyle}>{attachment.name}</div>
                <div style={detailValueStyle}>{formatBytes(attachment.size)}</div>
                {attachment.protectInMemory ? (
                  <span style={protectedBadgeStyle}>{text("Protected")}</span>
                ) : null}
                <button
                  type="button"
                  aria-label={`Download ${attachment.name}`}
                  onClick={() => onDownloadAttachment?.(attachment.name)}
                  style={secondaryActionStyle}
                >
                  {text("Download")}
                </button>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function EntryHistorySection({
  items,
  detail,
  error,
  text,
  onSelect
}: {
  items: EntryHistoryItem[];
  detail: EntryHistoryDetail | null;
  error: string | null;
  text: ReturnType<typeof useText>;
  onSelect?: (historyIndex: number) => void;
}) {
  if (items.length === 0 && !detail && !error) {
    return null;
  }

  return (
    <section aria-label={text("History")} style={sectionStyle}>
      <h3 style={sectionTitleStyle}>{text("History")}</h3>
      {error ? (
        <div role="alert" style={detailValueStyle}>
          {error}
        </div>
      ) : null}
      {items.length > 0 ? (
        <div style={detailListStyle}>
          {items.map((item) => (
            <button
              key={item.index}
              type="button"
              aria-label={`View history ${item.index + 1}`}
              onClick={() => onSelect?.(item.index)}
              style={historyButtonStyle}
            >
              <span style={detailKeyStyle}>{item.title || text("Untitled Entry")}</span>
              <span style={detailValueStyle}>{item.username}</span>
              <span style={detailValueStyle}>{formatUnixTimestamp(item.modifiedAt)}</span>
              <span style={detailValueStyle}>
                {item.attachmentCount} {text("Attachments")} / {item.customFieldCount} {text("Additional Properties")}
              </span>
            </button>
          ))}
        </div>
      ) : null}
      {detail ? <EntryHistoryDetailView detail={detail} text={text} /> : null}
    </section>
  );
}

function EntryHistoryDetailView({
  detail,
  text
}: {
  detail: EntryHistoryDetail;
  text: ReturnType<typeof useText>;
}) {
  return (
    <section aria-label={text("History Detail")} style={sectionStyle}>
      <h3 style={sectionTitleStyle}>{text("History Detail")}</h3>
      <div style={detailListStyle}>
        <div style={detailRowStyle}>
          <div style={detailKeyStyle}>{text("Title")}</div>
          <div style={detailValueStyle}>{detail.title}</div>
        </div>
        {typeof detail.modifiedAt === "number" ? (
          <div style={detailRowStyle}>
            <div style={detailKeyStyle}>{text("Modified At")}</div>
            <div style={detailValueStyle}>{formatUnixTimestamp(detail.modifiedAt)}</div>
          </div>
        ) : null}
        <div style={detailRowStyle}>
          <div style={detailKeyStyle}>{text("Username")}</div>
          <div style={detailValueStyle}>{detail.username}</div>
        </div>
        <div style={detailRowStyle}>
          <div style={detailKeyStyle}>{text("Password")}</div>
          <div style={detailValueStyle}>************</div>
        </div>
        <div style={detailRowStyle}>
          <div style={detailKeyStyle}>URL</div>
          <div style={detailValueStyle}>{detail.url}</div>
        </div>
        <div style={detailRowStyle}>
          <div style={detailKeyStyle}>{text("Notes")}</div>
          <div style={detailValueStyle}>{detail.notes}</div>
        </div>
        {detail.customFields.map((field) => (
          <div key={field.key} style={detailRowStyle}>
            <div style={detailKeyStyle}>{field.key}</div>
            <div style={detailValueStyle}>
              {field.protected ? "************" : field.value}
            </div>
          </div>
        ))}
        {detail.attachments.map((attachment) => (
          <div key={attachment.name} style={detailRowStyle}>
            <div style={detailKeyStyle}>{attachment.name}</div>
            <div style={detailValueStyle}>{formatBytes(attachment.size)}</div>
            {attachment.protectInMemory ? (
              <span style={protectedBadgeStyle}>{text("Protected")}</span>
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function Field({
  label,
  value,
  editable,
  onChange
}: {
  label: string;
  value: string;
  editable: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label
      style={{
        display: "grid",
        gap: archiveTheme.spacing.xs,
        fontFamily: archiveTheme.font.body
      }}
    >
      {label}
      <input
        type="text"
        readOnly={!editable}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        style={fieldStyle}
      />
    </label>
  );
}

const fieldStyle = {
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

const notesStyle = {
  ...fieldStyle,
  minHeight: "130px",
  resize: "vertical" as const
};

const privateKeyPemDraftStyle = {
  ...fieldStyle,
  minHeight: "150px",
  resize: "vertical" as const,
  fontFamily: "monospace",
  whiteSpace: "pre-wrap" as const
};

const concealedPrivateKeyPemDraftStyle = {
  ...privateKeyPemDraftStyle,
  WebkitTextSecurity: "disc"
};

const fieldLabelStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  minWidth: 0,
  fontFamily: archiveTheme.font.body
};

const generatorPanelStyle = {
  display: "grid",
  gap: archiveTheme.spacing.sm,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.md,
  background: "rgba(255, 251, 244, 0.72)"
};

const generatorControlsStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
  gap: archiveTheme.spacing.sm,
  alignItems: "end"
};

const inlineActionsStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  gap: archiveTheme.spacing.sm,
  justifyContent: "flex-end"
};

const checkboxLabelStyle = {
  display: "flex",
  alignItems: "center",
  gap: archiveTheme.spacing.xs,
  paddingBottom: archiveTheme.spacing.sm,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  whiteSpace: "nowrap" as const
};

const secondaryActionStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const primaryActionStyle = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: archiveTheme.font.body
};

const saveButtonContentStyle = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: archiveTheme.spacing.xs,
  minWidth: "96px"
};

const saveSpinnerStyle = {
  width: "0.9rem",
  height: "0.9rem",
  border: "2px solid rgba(255, 250, 242, 0.45)",
  borderTopColor: "#fffaf2",
  borderRadius: "999px",
  animation: "vaultkern-save-spin 0.8s linear infinite",
  boxSizing: "border-box" as const
};

const dangerActionStyle = {
  border: `1px solid ${archiveTheme.colors.danger}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: "rgba(139, 61, 42, 0.12)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const sectionStyle = {
  display: "grid",
  gap: archiveTheme.spacing.sm
};

const sectionHeaderStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  alignItems: "center",
  justifyContent: "space-between",
  gap: archiveTheme.spacing.sm
};

const sectionTitleStyle = {
  margin: 0,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.display,
  fontSize: "1rem",
  fontWeight: 600
};

const detailListStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs
};

const detailRowStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(120px, 0.8fr) minmax(0, 1fr) auto",
  gap: archiveTheme.spacing.sm,
  alignItems: "center",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: archiveTheme.colors.surfaceMuted,
  minWidth: 0
};

const detailKeyStyle = {
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  overflowWrap: "anywhere" as const
};

const detailValueStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.body,
  overflowWrap: "anywhere" as const
};

const metadataTextStyle = {
  ...detailValueStyle,
  fontSize: "0.9rem"
};

const protectedBadgeStyle = {
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.xs} ${archiveTheme.spacing.sm}`,
  background: "rgba(139, 61, 42, 0.10)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.82rem",
  whiteSpace: "nowrap" as const
};

const protectedToggleStyle = {
  ...protectedBadgeStyle,
  border: `1px solid ${archiveTheme.colors.danger}`,
  cursor: "pointer"
};

const historyButtonStyle = {
  ...detailRowStyle,
  width: "100%",
  textAlign: "left" as const,
  cursor: "pointer"
};

const editableFieldListStyle = {
  display: "grid",
  gap: archiveTheme.spacing.sm
};

const sensitiveDraftFieldStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) auto",
  gap: archiveTheme.spacing.sm,
  alignItems: "end",
  minWidth: 0
};

const editableFieldRowStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(110px, 0.8fr) minmax(0, 1.1fr) auto auto",
  gap: archiveTheme.spacing.sm,
  alignItems: "end",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: archiveTheme.colors.surfaceMuted,
  minWidth: 0
};

const attachmentEditRowStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(150px, 1fr) auto auto auto auto",
  gap: archiveTheme.spacing.sm,
  alignItems: "end",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: archiveTheme.colors.surfaceMuted,
  minWidth: 0
};

const inlineFieldStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  minWidth: 0,
  fontFamily: archiveTheme.font.body
};

const checkboxFieldStyle = {
  display: "flex",
  alignItems: "center",
  gap: archiveTheme.spacing.xs,
  paddingBottom: archiveTheme.spacing.sm,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  whiteSpace: "nowrap" as const
};

const dangerSmallButtonStyle = {
  border: `1px solid ${archiveTheme.colors.danger}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: "rgba(139, 61, 42, 0.12)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

const hiddenFileInputStyle = {
  width: 1,
  height: 1,
  opacity: 0,
  position: "absolute" as const,
  pointerEvents: "none" as const
};

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }

  const kib = size / 1024;
  if (kib < 1024) {
    return `${kib.toFixed(kib >= 10 ? 0 : 1)} KiB`;
  }

  const mib = kib / 1024;
  return `${mib.toFixed(mib >= 10 ? 0 : 1)} MiB`;
}

function formatUnixTimestamp(seconds: number): string {
  const date = new Date(seconds * 1000);
  const parts = [
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds()
  ].map((part) => String(part).padStart(2, "0"));

  return `${parts[0]}-${parts[1]}-${parts[2]} ${parts[3]}:${parts[4]}:${parts[5]}`;
}
