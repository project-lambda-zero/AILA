/**
 * TagVocabularyModal -- admin-managed asset-tag vocabulary editor, folded into
 * the Systems view (req 48). The vocabulary governs which tag keys an operator
 * may assign to a system (POST /tags/systems/{id} rejects any key absent here),
 * so managing it lives next to the systems it governs rather than as a
 * standalone admin page. All three endpoints require the admin role; render
 * this modal only for admins.
 */
import { useState, type JSX } from "react";

import { apiErrDetail } from "../../../api/parse";
import {
  useCreateVocabEntry,
  useDeleteVocabEntry,
  useTagVocabulary,
} from "../../../api/systems";
import { css } from "../../css";

const TAG_KEY_RE = /^[a-z0-9_-]+$/;

interface Props {
  onClose: () => void;
}

export default function TagVocabularyModal(props: Props): JSX.Element {
  const vocabQ = useTagVocabulary(true);
  const create = useCreateVocabEntry();
  const del = useDeleteVocabEntry();
  const [tagKey, setTagKey] = useState<string>("");
  const [description, setDescription] = useState<string>("");
  const [formError, setFormError] = useState<string | null>(null);

  const entries = vocabQ.data ?? [];

  const doAdd = (): void => {
    const key = tagKey.trim();
    if (!key) {
      setFormError("tag key is required");
      return;
    }
    if (!TAG_KEY_RE.test(key)) {
      setFormError("tag key must match ^[a-z0-9_-]+$");
      return;
    }
    setFormError(null);
    create.mutate(
      { tag_key: key, description: description.trim() },
      {
        onSuccess: () => {
          setTagKey("");
          setDescription("");
        },
      },
    );
  };

  return (
    <div
      style={css(
        "position:fixed;inset:0;z-index:64;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:24px;",
      )}
      onClick={props.onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={css(
          "width:100%;max-width:560px;max-height:100%;overflow:auto;background:var(--surface-card);border:1px solid var(--border);border-radius:4px;box-shadow:0 12px 60px rgba(0,0,0,0.6);display:flex;flex-direction:column;",
        )}
      >
        <div
          style={css(
            "display:flex;align-items:center;gap:8px;padding:11px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);background-image:repeating-linear-gradient(135deg,var(--border-soft) 0 1px,transparent 1px 4px);",
          )}
        >
          <span style={css("width:8px;height:8px;background:var(--accent);box-shadow:0 0 6px var(--accent);")} />
          <span style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>
            tag vocabulary
          </span>
          <span style={css("flex:1;")} />
          <button
            type="button"
            onClick={props.onClose}
            style={css("width:24px;height:24px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;color:var(--text-muted);cursor:pointer;font-size:12px;")}
          >
            {"\u2715"}
          </button>
        </div>

        <div style={css("padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>
          <span style={css("font-size:11px;color:var(--text-muted);line-height:1.5;")}>
            Tag keys an operator may assign to a system. Add a key here before it
            can be assigned {"\u2014"} an unknown key is rejected at assignment time.
          </span>

          <div>
            <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);margin-bottom:6px;")}>
              vocabulary {entries.length ? "(" + entries.length + ")" : ""}
            </div>
            <div style={css("border:1px solid var(--border-soft);border-radius:4px;overflow:hidden;")}>
              {vocabQ.isLoading ? (
                <div style={css("padding:18px;text-align:center;font-size:11px;color:var(--text-faint);")}>loading {"\u2026"}</div>
              ) : vocabQ.isError ? (
                <div style={css("padding:18px;text-align:center;font-size:11px;color:var(--status-warn);")}>
                  could not load vocabulary {"\u2014"} {apiErrDetail(vocabQ.error)}
                </div>
              ) : entries.length === 0 ? (
                <div style={css("padding:20px;text-align:center;font-size:11px;color:var(--text-muted);")}>
                  no tag keys yet {"\u2014"} add one below.
                </div>
              ) : entries.map((v) => (
                <div
                  key={v.id}
                  style={css("display:grid;grid-template-columns:150px 1fr auto;gap:10px;align-items:center;padding:7px 11px;border-bottom:1px solid var(--border-faint);")}
                >
                  <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{v.tag_key}</span>
                  <span style={css("font-size:10.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{v.description || "\u2014"}</span>
                  {v.is_system_default ? (
                    <span style={css("font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);border:1px solid var(--border-soft);border-radius:2px;padding:2px 6px;")}>default</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => del.mutate(v.tag_key)}
                      disabled={del.isPending}
                      style={css("padding:0 8px;height:22px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;color:#ff5f87;background:transparent;border:1px solid #ff5f8759;border-radius:2px;cursor:pointer;")}
                    >
                      remove
                    </button>
                  )}
                </div>
              ))}
            </div>
            {del.isError ? (
              <div style={css("margin-top:6px;font-size:10.5px;color:var(--status-warn);")}>
                remove failed {"\u2014"} {apiErrDetail(del.error)}
              </div>
            ) : null}
          </div>

          <div style={css("border-top:1px solid var(--border-soft);padding-top:12px;display:flex;flex-direction:column;gap:9px;")}>
            <span style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>new tag key</span>
            <label style={css("display:flex;flex-direction:column;gap:5px;")}>
              <span style={css("font-size:10.5px;letter-spacing:0.06em;color:var(--text-primary);")}>tag key</span>
              <input
                type="text"
                value={tagKey}
                onChange={(e) => { setTagKey(e.target.value); setFormError(null); }}
                placeholder="lowercase alphanumeric + underscore/hyphen"
                style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:3px;")}
              />
              <span style={css("font-size:9.5px;color:var(--text-faint);")}>pattern ^[a-z0-9_-]+$</span>
            </label>
            <label style={css("display:flex;flex-direction:column;gap:5px;")}>
              <span style={css("font-size:10.5px;letter-spacing:0.06em;color:var(--text-primary);")}>description</span>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                style={css("resize:vertical;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;line-height:1.45;border-radius:3px;")}
              />
            </label>
            {formError ? <div style={css("font-size:11px;color:var(--status-warn);")}>{formError}</div> : null}
            {create.isError ? <div style={css("font-size:11px;color:var(--status-warn);")}>{"server: " + apiErrDetail(create.error)}</div> : null}
            <div style={css("display:flex;justify-content:flex-end;")}>
              <button
                type="button"
                onClick={doAdd}
                disabled={create.isPending}
                style={css("padding:0 14px;height:30px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:pointer;")}
              >
                {create.isPending ? "adding \u2026" : "add tag key"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
