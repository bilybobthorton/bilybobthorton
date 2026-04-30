"use client";

import { useEffect, useState } from "react";

interface YaraRule {
  id: string;
  name: string;
  description: string | null;
  rule_text: string;
  enabled: boolean;
  is_builtin: boolean;
  hit_count: string;
  created_at: string;
  updated_at: string;
}

interface ValidateResult {
  valid: boolean;
  error?: string;
  rule_count?: number;
  rules?: string[];
}

const STARTER_RULE = `rule My_Custom_Rule {
    meta:
        description = "Describe what this rule detects"
        severity = "high"
    strings:
        $s1 = "suspicious_string" nocase
        $s2 = { 4D 5A 90 00 }
    condition:
        any of them
}`;

export default function YaraPage() {
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<YaraRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);

  // Editor state
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editText, setEditText] = useState(STARTER_RULE);
  const [editEnabled, setEditEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Validator
  const [validateResult, setValidateResult] = useState<ValidateResult | null>(null);
  const [validating, setValidating] = useState(false);

  const fetchRules = async () => {
    try {
      const res = await fetch("/api/v1/yara/rules");
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      setRules(await res.json());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load rules");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchRules(); }, []);

  const validate = async (text: string) => {
    setValidating(true);
    setValidateResult(null);
    try {
      const res = await fetch("/api/v1/yara/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_text: text }),
      });
      setValidateResult(await res.json());
    } catch {
      setValidateResult({ valid: false, error: "Validation request failed" });
    } finally {
      setValidating(false);
    }
  };

  const openCreate = () => {
    setSelected(null);
    setEditName("");
    setEditDesc("");
    setEditText(STARTER_RULE);
    setEditEnabled(true);
    setSaveError(null);
    setValidateResult(null);
    setShowEditor(true);
  };

  const openEdit = (rule: YaraRule) => {
    if (rule.is_builtin) { setSelected(rule); setShowEditor(false); return; }
    setSelected(rule);
    setEditName(rule.name);
    setEditDesc(rule.description ?? "");
    setEditText(rule.rule_text);
    setEditEnabled(rule.enabled);
    setSaveError(null);
    setValidateResult(null);
    setShowEditor(true);
  };

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      const isEdit = !!selected && !selected.is_builtin;
      const url = isEdit ? `/api/v1/yara/rules/${selected!.id}` : "/api/v1/yara/rules";
      const method = isEdit ? "PATCH" : "POST";
      const body = isEdit
        ? { description: editDesc, rule_text: editText, enabled: editEnabled }
        : { name: editName, description: editDesc, rule_text: editText, enabled: editEnabled };

      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? "Save failed");
      }

      await fetchRules();
      setShowEditor(false);
    } catch (e: unknown) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const deleteRule = async (rule: YaraRule) => {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    await fetch(`/api/v1/yara/rules/${rule.id}`, { method: "DELETE" });
    await fetchRules();
    if (showEditor && selected?.id === rule.id) setShowEditor(false);
  };

  const toggleEnabled = async (rule: YaraRule) => {
    if (rule.is_builtin) return;
    await fetch(`/api/v1/yara/rules/${rule.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    await fetchRules();
  };

  const builtins = rules.filter((r) => r.is_builtin);
  const custom = rules.filter((r) => !r.is_builtin);

  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">YARA Rules</h1>
          <p className="text-slate-500 text-sm mt-1">
            {builtins.length} built-in · {custom.length} custom
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-semibold rounded-lg transition-colors"
        >
          + New Rule
        </button>
      </div>

      {error && (
        <div className="rounded-lg bg-red-900/20 border border-red-800 px-4 py-3 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Rule list */}
        <div className="space-y-3">
          {loading ? (
            <p className="text-slate-500 text-sm">Loading rules...</p>
          ) : (
            <>
              {builtins.length > 0 && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">Built-in</p>
                  {builtins.map((r) => (
                    <RuleCard key={r.id} rule={r} onEdit={openEdit} onDelete={deleteRule} onToggle={toggleEnabled} />
                  ))}
                </div>
              )}
              {custom.length > 0 && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wide mb-2 mt-4">Custom</p>
                  {custom.map((r) => (
                    <RuleCard key={r.id} rule={r} onEdit={openEdit} onDelete={deleteRule} onToggle={toggleEnabled} />
                  ))}
                </div>
              )}
              {rules.length === 0 && (
                <div className="rounded-lg border border-slate-800 p-8 text-center">
                  <p className="text-slate-500 text-sm">No rules yet.</p>
                </div>
              )}
            </>
          )}
        </div>

        {/* Editor / detail panel */}
        {showEditor && (
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-5 space-y-4">
            <h2 className="text-white font-semibold">
              {selected && !selected.is_builtin ? `Edit: ${selected.name}` : "New Rule"}
            </h2>

            {!selected && (
              <div>
                <label className="text-xs text-slate-500 uppercase tracking-wide">Rule Name</label>
                <input
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="My_Detection_Rule"
                  className="mt-1 w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded px-3 py-2 font-mono focus:outline-none focus:border-slate-500"
                />
              </div>
            )}

            <div>
              <label className="text-xs text-slate-500 uppercase tracking-wide">Description</label>
              <input
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                placeholder="What does this rule detect?"
                className="mt-1 w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-slate-500"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-slate-500 uppercase tracking-wide">Rule Text</label>
                <button
                  onClick={() => validate(editText)}
                  disabled={validating}
                  className="text-xs text-slate-400 hover:text-white border border-slate-700 px-2 py-0.5 rounded transition-colors"
                >
                  {validating ? "Validating..." : "Validate"}
                </button>
              </div>
              <textarea
                value={editText}
                onChange={(e) => { setEditText(e.target.value); setValidateResult(null); }}
                rows={14}
                spellCheck={false}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded px-3 py-2 font-mono focus:outline-none focus:border-slate-500 resize-none"
              />
              {validateResult && (
                <div className={`mt-1.5 text-xs px-3 py-1.5 rounded ${
                  validateResult.valid
                    ? "bg-green-900/30 border border-green-800 text-green-400"
                    : "bg-red-900/30 border border-red-800 text-red-400"
                }`}>
                  {validateResult.valid
                    ? `✓ Valid — ${validateResult.rule_count} rule(s): ${validateResult.rules?.join(", ")}`
                    : `✗ ${validateResult.error}`}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                checked={editEnabled}
                onChange={(e) => setEditEnabled(e.target.checked)}
                className="accent-red-600"
              />
              <label htmlFor="enabled" className="text-sm text-slate-300">Enabled</label>
            </div>

            {saveError && (
              <div className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded px-3 py-1.5">
                {saveError}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={save}
                disabled={saving}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50"
              >
                {saving ? "Saving..." : "Save Rule"}
              </button>
              <button
                onClick={() => setShowEditor(false)}
                className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Read-only builtin detail */}
        {!showEditor && selected?.is_builtin && (
          <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-white font-semibold">{selected.name}</h2>
              <span className="text-xs text-slate-500 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded">Built-in</span>
            </div>
            {selected.description && <p className="text-slate-400 text-sm">{selected.description}</p>}
            <pre className="text-xs text-slate-300 bg-slate-950 rounded px-3 py-3 overflow-x-auto font-mono whitespace-pre-wrap">
              {selected.rule_text}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function RuleCard({
  rule,
  onEdit,
  onDelete,
  onToggle,
}: {
  rule: YaraRule;
  onEdit: (r: YaraRule) => void;
  onDelete: (r: YaraRule) => void;
  onToggle: (r: YaraRule) => void;
}) {
  return (
    <div
      className={`flex items-center gap-3 rounded-lg border px-4 py-3 mb-2 cursor-pointer hover:border-slate-600 transition-colors ${
        rule.enabled ? "border-slate-800 bg-slate-900/30" : "border-slate-800 bg-slate-900/10 opacity-60"
      }`}
      onClick={() => onEdit(rule)}
    >
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white font-medium truncate">{rule.name}</p>
        {rule.description && (
          <p className="text-xs text-slate-500 truncate">{rule.description}</p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-xs text-slate-600">{rule.hit_count} hits</span>
        {!rule.is_builtin && (
          <>
            <button
              onClick={(e) => { e.stopPropagation(); onToggle(rule); }}
              className={`text-xs px-2 py-0.5 rounded border transition-colors ${
                rule.enabled
                  ? "border-green-800 text-green-500 bg-green-900/20 hover:bg-green-900/40"
                  : "border-slate-700 text-slate-500 bg-slate-800 hover:bg-slate-700"
              }`}
            >
              {rule.enabled ? "On" : "Off"}
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); onDelete(rule); }}
              className="text-xs text-slate-600 hover:text-red-400 transition-colors"
            >
              ✕
            </button>
          </>
        )}
        {rule.is_builtin && (
          <span className="text-xs text-slate-600 border border-slate-800 px-2 py-0.5 rounded">built-in</span>
        )}
      </div>
    </div>
  );
}
