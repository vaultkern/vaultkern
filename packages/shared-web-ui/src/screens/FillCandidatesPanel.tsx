import type { EntrySummary } from "@vaultkern/runtime-web-client";

export function FillCandidatesPanel({
  candidates,
  onFill
}: {
  candidates: EntrySummary[];
  onFill: (entryId: string) => Promise<void>;
}) {
  if (candidates.length === 0) {
    return <div>No fill candidates for this page.</div>;
  }

  return (
    <div>
      {candidates.map((entry) => (
        <button key={entry.id} type="button" onClick={() => void onFill(entry.id)}>
          Fill {entry.title}
        </button>
      ))}
    </div>
  );
}
