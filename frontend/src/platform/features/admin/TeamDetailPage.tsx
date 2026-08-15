/**
 * TeamDetailPage -- admin-only team detail with member management (Phase 177).
 *
 * Shows a single team with full member list. Admins can:
 *  - Rename / update description.
 *  - Add members by user id with a role.
 *  - Remove members.
 *  - Delete the team (blocked if systems still reference it).
 *
 * Presentation rebuilt to the AILA mock language. Data hooks, mutations,
 * route params, and testids preserved.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router";

import { SectionHeader, DataGrid, MonoBadge, FilterChip } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Team {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  member_count: number;
}

interface TeamMember {
  id: string;
  user_id: string;
  username: string;
  email: string | null;
  role: string;
  created_at: string;
}

interface TeamDetail {
  team: Team;
  members: TeamMember[];
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface UpdateTeamRequest {
  name?: string;
  description?: string;
}

interface AddMemberRequest {
  user_id: string;
  role: "admin" | "operator" | "reader";
}

// ---------------------------------------------------------------------------
// Local mock styles
// ---------------------------------------------------------------------------

const btnBase: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  letterSpacing: "0.08em",
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  textTransform: "uppercase",
  fontFamily: "var(--font-mono)",
};

const primaryBtn: React.CSSProperties = {
  ...btnBase,
  background: "var(--accent)",
  color: "var(--text-on-accent)",
  borderColor: "var(--accent)",
};

const dangerBtn: React.CSSProperties = {
  ...btnBase,
  color: "var(--status-warn)",
  borderColor: "color-mix(in srgb, var(--status-warn) 40%, transparent)",
};

const inputStyle: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  width: "100%",
};

const labelStyle: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
  color: "var(--text-faint)",
};

function ErrorLine({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
        background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
        color: "var(--status-warn)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

function ModalFrame({
  open,
  onClose,
  title,
  children,
  width = 420,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: number;
}) {
  if (!open) return null;
  return (
    <div
      className="flex items-center justify-center"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
      }}
      onClick={onClose}
      role="presentation"
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: "94vw" }}>
        <WindowPanel
          title={title}
          tone="accent"
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="font-mono"
              style={{
                width: 20,
                height: 20,
                border: 0,
                background: "transparent",
                color: "var(--text-muted)",
                cursor: "pointer",
                fontSize: 13,
                lineHeight: 1,
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function roleTone(role: string): string {
  if (role === "admin") return "critical";
  if (role === "operator") return "medium";
  return "muted";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Add member modal
// ---------------------------------------------------------------------------

function AddMemberButton({
  onAdd,
  isPending,
}: {
  onAdd: (req: AddMemberRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<AddMemberRequest["role"]>("operator");
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setUserId("");
      setRole("operator");
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await onAdd({ user_id: userId, role });
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add member");
    }
  }

  return (
    <>
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Add member
      </button>

      <ModalFrame open={open} onClose={handleClose} title="add team member">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="am-user">user id</label>
            <input
              id="am-user"
              style={inputStyle}
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="am-role">role</label>
            <select
              id="am-role"
              style={inputStyle}
              value={role}
              onChange={(e) => setRole(e.target.value as AddMemberRequest["role"])}
            >
              <option value="reader">reader</option>
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
          </div>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              style={{ ...primaryBtn, flex: 1 }}
              disabled={isPending}
            >
              {isPending ? "Adding..." : "Add member"}
            </button>
            <button type="button" style={btnBase} onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Rename modal
// ---------------------------------------------------------------------------

function EditTeamButton({
  team,
  onUpdate,
  isPending,
}: {
  team: Team;
  onUpdate: (req: UpdateTeamRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(team.name);
  const [description, setDescription] = useState(team.description);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setName(team.name);
      setDescription(team.description);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const diff: UpdateTeamRequest = {};
      if (name !== team.name) diff.name = name;
      if (description !== team.description) diff.description = description;
      if (Object.keys(diff).length === 0) {
        handleClose();
        return;
      }
      await onUpdate(diff);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update team");
    }
  }

  return (
    <>
      <button type="button" style={btnBase} onClick={() => setOpen(true)}>
        Edit
      </button>

      <ModalFrame open={open} onClose={handleClose} title="edit team">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="rt-name">name</label>
            <input
              id="rt-name"
              style={inputStyle}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="rt-desc">description</label>
            <input
              id="rt-desc"
              style={inputStyle}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              style={{ ...primaryBtn, flex: 1 }}
              disabled={isPending}
            >
              {isPending ? "Saving..." : "Save"}
            </button>
            <button type="button" style={btnBase} onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Delete modal
// ---------------------------------------------------------------------------

function DeleteTeamButton({
  team,
  onDelete,
  isPending,
}: {
  team: Team;
  onDelete: () => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onDelete();
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete team");
    }
  }

  return (
    <>
      <button type="button" style={dangerBtn} onClick={() => setOpen(true)}>
        Delete
      </button>

      <ModalFrame
        open={open}
        onClose={() => setOpen(false)}
        title="delete team"
        width={420}
      >
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            Deleting{" "}
            <span style={{ color: "var(--accent)" }}>{team.name}</span> removes
            all memberships. The backend will reject if any managed systems
            still reference this team.
          </p>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{
                ...primaryBtn,
                flex: 1,
                background: "var(--status-warn)",
                borderColor: "var(--status-warn)",
              }}
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Deleting..." : "Confirm delete"}
            </button>
            <button
              type="button"
              style={btnBase}
              onClick={() => setOpen(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TeamDetailPage() {
  const { id: teamId = "" } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const detailQuery = useQuery({
    queryKey: ["platform", "admin-teams", teamId],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<TeamDetail>>(`/admin/teams/${teamId}`),
    enabled: teamId.length > 0,
  });

  const updateMutation = useMutation({
    mutationFn: (req: UpdateTeamRequest) =>
      authorizedRequestJson<DataEnvelope<Team>>(`/admin/teams/${teamId}`, {
        method: "PUT",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<{ deleted: string }>>(
        `/admin/teams/${teamId}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
      navigate("/admin/teams");
    },
  });

  const addMemberMutation = useMutation({
    mutationFn: (req: AddMemberRequest) =>
      authorizedRequestJson<DataEnvelope<TeamMember>>(
        `/admin/teams/${teamId}/members`,
        { method: "POST", body: req },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams", teamId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) =>
      authorizedRequestJson<DataEnvelope<{ removed: string }>>(
        `/admin/teams/${teamId}/members/${userId}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams", teamId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const detail = detailQuery.data?.data;
  const members = detail?.members ?? [];

  useUpdatePageHeader({
    title: detail?.team?.name,
    subtitle: detail?.team?.description || undefined,
    status: null,
  });

  const memberByRole = useMemo(() => {
    const r: Record<string, number> = { admin: 0, operator: 0, reader: 0 };
    for (const m of members) r[m.role] = (r[m.role] ?? 0) + 1;
    return r;
  }, [members]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      {detailQuery.isLoading && (
        <WindowPanel title="team" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {detailQuery.isError && (
        <ErrorLine>
          Failed to load team: {(detailQuery.error as Error).message}
        </ErrorLine>
      )}

      {detail && (
        <>
          <SectionHeader
            icon={"\u25ce"}
            title={detail.team.name}
            actions={
              <div className="flex" style={{ gap: 6 }}>
                <button
                  type="button"
                  style={btnBase}
                  onClick={() => navigate("/admin/teams")}
                >
                  {"\u2190"} Back
                </button>
                <EditTeamButton
                  team={detail.team}
                  onUpdate={(req) => updateMutation.mutateAsync(req)}
                  isPending={updateMutation.isPending}
                />
                <DeleteTeamButton
                  team={detail.team}
                  onDelete={() => deleteMutation.mutateAsync()}
                  isPending={deleteMutation.isPending}
                />
              </div>
            }
          />

          {detail.team.description && (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -8 }}
            >
              {detail.team.description}
            </p>
          )}

          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <WindowPanel title="members">
              <div className="flex items-baseline" style={{ gap: 8 }}>
                <span
                  className="font-mono"
                  style={{ fontSize: 26, color: "var(--accent)" }}
                >
                  {members.length}
                </span>
                <span
                  className="font-mono uppercase"
                  style={{ fontSize: 9.5, letterSpacing: "0.1em", color: "var(--text-faint)" }}
                >
                  active
                </span>
              </div>
            </WindowPanel>
            <WindowPanel title="created">
              <span
                className="font-mono"
                style={{ fontSize: 12, color: "var(--text-primary)" }}
              >
                {formatTimestamp(detail.team.created_at)}
              </span>
            </WindowPanel>
            <WindowPanel title="updated">
              <span
                className="font-mono"
                style={{ fontSize: 12, color: "var(--text-primary)" }}
              >
                {formatTimestamp(detail.team.updated_at)}
              </span>
            </WindowPanel>
          </div>

          <WindowPanel
            title="members"
            actions={
              <AddMemberButton
                onAdd={(req) => addMemberMutation.mutateAsync(req)}
                isPending={addMemberMutation.isPending}
              />
            }
            flush
          >
            {members.length === 0 ? (
              <div
                className="flex flex-col items-center font-mono"
                style={{ padding: "36px 12px", gap: 8 }}
              >
                <span style={{ fontSize: 14, color: "var(--text-primary)" }}>
                  No members
                </span>
                <span style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", maxWidth: 380 }}>
                  Add a user to this team to grant access to team-scoped resources.
                </span>
              </div>
            ) : (
              <DataGrid
                columns={[
                  { label: "USER", width: "1.4fr" },
                  { label: "ROLE", width: "110px" },
                  { label: "JOINED", width: "180px" },
                  { label: "ACTIONS", width: "110px", align: "right" },
                ]}
                rows={members}
                getKey={(m) => m.id}
                renderCells={(m) => [
                  <div key="u" className="flex flex-col">
                    <span
                      className="font-mono"
                      style={{ fontSize: 11.5, color: "var(--text-primary)" }}
                    >
                      {m.username}
                    </span>
                    {m.email && (
                      <span
                        className="font-mono"
                        style={{ fontSize: 10, color: "var(--text-faint)" }}
                      >
                        {m.email}
                      </span>
                    )}
                  </div>,
                  <MonoBadge key="r" tone={roleTone(m.role)}>{m.role}</MonoBadge>,
                  <span
                    key="j"
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
                  >
                    {formatTimestamp(m.created_at)}
                  </span>,
                  <button
                    key="a"
                    type="button"
                    style={dangerBtn}
                    disabled={removeMemberMutation.isPending}
                    onClick={() => {
                      void removeMemberMutation.mutateAsync(m.user_id).catch(() => undefined);
                    }}
                    aria-label={`Remove member ${m.username}`}
                  >
                    Remove
                  </button>,
                ]}
              />
            )}
          </WindowPanel>

          <WindowPanel title="permissions">
            <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
              <FilterChip active color="var(--accent)">
                ADMIN {memberByRole.admin ?? 0}
              </FilterChip>
              <FilterChip active color="var(--status-info)">
                OPERATOR {memberByRole.operator ?? 0}
              </FilterChip>
              <FilterChip active color="var(--status-ok)">
                READER {memberByRole.reader ?? 0}
              </FilterChip>
              <span
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", marginLeft: 8 }}
              >
                role distribution across current members
              </span>
            </div>
          </WindowPanel>

          <WindowPanel title="saved filters" flush>
            <div
              className="font-mono"
              style={{
                padding: 22,
                textAlign: "center",
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              team-scoped saved filters surface here once shared with the team.
            </div>
          </WindowPanel>

          <WindowPanel title="activity">
            <div
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                lineHeight: 1.55,
              }}
            >
              Team created {formatTimestamp(detail.team.created_at)}
              {detail.team.updated_at !== detail.team.created_at &&
                `, last updated ${formatTimestamp(detail.team.updated_at)}`}
              . {members.length} member{members.length === 1 ? "" : "s"}.
            </div>
          </WindowPanel>
        </>
      )}
    </div>
  );
}
