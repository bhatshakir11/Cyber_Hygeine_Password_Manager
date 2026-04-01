import React, { useMemo, useState, useEffect } from "react";
import Navbar from "../components/Navbar";
import AnimatedBackground from "../components/AnimatedBackground";
import zxcvbn from "zxcvbn";
import apiClient from "../apiClient";

// Password strength checker using zxcvbn
function getPasswordStrength(password) {
  const result = zxcvbn(password);
  const score = result.score;
  if (score <= 1) return "weak";
  if (score === 2) return "medium";
  return "strong";
}

const strengthColors = {
  weak: "bg-red-600",
  medium: "bg-yellow-600",
  strong: "bg-green-600"
};

const suggestionWords = [
  "orbit",
  "ember",
  "harbor",
  "quartz",
  "cinder",
  "vector",
  "summit",
  "signal",
  "nova",
  "atlas",
  "cobalt",
  "lumen",
  "cipher",
  "anchor",
  "rocket",
  "sage",
  "delta",
  "falcon",
  "tidal",
  "grove"
];

const suggestionSymbols = ["!", "@", "#", "$", "%", "&", "*"];

function uniqueItems(items) {
  return [...new Set(items.filter(Boolean))];
}

function normalizeFragment(value) {
  return (value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function passwordContainsPersonalInfo(password, site, username) {
  const normalizedPassword = normalizeFragment(password);
  const fragments = [
    normalizeFragment(site).split(".")[0],
    normalizeFragment(username).split("@")[0]
  ]
    .filter(Boolean)
    .filter((fragment) => fragment.length >= 3);

  return fragments.some((fragment) => normalizedPassword.includes(fragment));
}

function getRandomInt(max) {
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0] % max;
  }
  return Math.floor(Math.random() * max);
}

function buildStrongPasswordIdeas() {
  const ideas = [];

  while (ideas.length < 3) {
    const words = [];
    while (words.length < 3) {
      const nextWord = suggestionWords[getRandomInt(suggestionWords.length)];
      if (!words.includes(nextWord)) {
        words.push(nextWord);
      }
    }

    const number = 100 + getRandomInt(900);
    const symbol = suggestionSymbols[getRandomInt(suggestionSymbols.length)];
    const candidate = `${words[0]}-${words[1]}-${words[2]}${symbol}${number}`;
    ideas.push(candidate);
  }

  return ideas;
}

function buildAiSuggestions(password, site, username, credentials, result) {
  if (!password) {
    return {
      headline: "Start typing a password to get upgrade suggestions.",
      issues: [],
      actions: [],
      positives: [],
      reusedOn: 0
    };
  }

  const reusedOn = credentials.filter((cred) => cred.password === password).length;
  const issues = [];
  const actions = [];
  const positives = [];

  if (password.length < 12) {
    issues.push("This password is short enough to crack faster than a modern passphrase.");
    actions.push("Move to at least 12-16 characters for a stronger baseline.");
  } else {
    positives.push("Length is heading in the right direction.");
  }

  if (!/[a-z]/.test(password)) actions.push("Add lowercase letters so the pattern is less predictable.");
  if (!/[A-Z]/.test(password)) actions.push("Add uppercase letters to widen the character mix.");
  if (!/\d/.test(password)) actions.push("Include numbers that are not obvious years or birthdays.");
  if (!/[^A-Za-z0-9]/.test(password)) {
    actions.push("Add a symbol to increase resistance against simple guessing attacks.");
  }

  if (passwordContainsPersonalInfo(password, site, username)) {
    issues.push("It appears to contain your site name or username, which makes it easier to guess.");
    actions.push("Avoid using account names, site names, or email fragments inside the password.");
  }

  if (reusedOn > 0) {
    issues.push(`This exact password is already used on ${reusedOn} other saved ${reusedOn === 1 ? "account" : "accounts"}.`);
    actions.push("Use a unique password for every site so one breach does not spread.");
  }

  if (result.feedback.warning) {
    issues.push(result.feedback.warning);
  }

  if (Array.isArray(result.feedback.suggestions)) {
    result.feedback.suggestions.forEach((suggestion) => actions.push(suggestion));
  }

  if (result.score >= 3 && reusedOn === 0 && !passwordContainsPersonalInfo(password, site, username)) {
    positives.push("This password already avoids the biggest red flags.");
  }

  let headline = "AI sees room to harden this password before you save it.";
  if (result.score >= 4 && reusedOn === 0) {
    headline = "This is in strong shape. You can still upgrade it if you want a safer backup option.";
  } else if (reusedOn > 0) {
    headline = "Biggest risk: this password is being reused across accounts.";
  } else if (result.score <= 1) {
    headline = "This password is easy to guess. Upgrade it before adding it to your vault.";
  }

  return {
    headline,
    issues: uniqueItems(issues).slice(0, 4),
    actions: uniqueItems(actions).slice(0, 5),
    positives: uniqueItems(positives).slice(0, 2),
    reusedOn
  };
}

const VaultPage = () => {
  const [credentials, setCredentials] = useState([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ site: "", username: "", password: "", strength: "medium" });
  const [zxcvbnResult, setZxcvbnResult] = useState(zxcvbn(""));
  const [passwordIdeas, setPasswordIdeas] = useState([]);
  const [error, setError] = useState("");
  const [removingId, setRemovingId] = useState(null);
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ site: "", username: "", password: "", strength: "medium" });
  const [editZxcvbnResult, setEditZxcvbnResult] = useState(zxcvbn(""));
  const [editPasswordIdeas, setEditPasswordIdeas] = useState([]);
  const [showPassword, setShowPassword] = useState({});
  const [showAddPassword, setShowAddPassword] = useState(false);
  const [showEditPassword, setShowEditPassword] = useState({});

  useEffect(() => {
    apiClient.get("/credentials").then((res) => {
      setCredentials(res.data);
    });
  }, []);

  useEffect(() => {
    if (!showAdd || !form.password) {
      setPasswordIdeas([]);
      return;
    }

    setPasswordIdeas(buildStrongPasswordIdeas());
  }, [showAdd, form.password]);

  useEffect(() => {
    if (!editingId || !editForm.password) {
      setEditPasswordIdeas([]);
      return;
    }

    setEditPasswordIdeas(buildStrongPasswordIdeas());
  }, [editingId, editForm.password]);

  const handleRemove = async (id) => {
    setRemovingId(id);
    setError("");
    try {
      await apiClient.delete(`/credentials/${id}`);
      setCredentials((current) => current.filter((cred) => cred.id !== id));
    } catch (err) {
      setError("Failed to remove credential.");
    }
    setRemovingId(null);
  };

  const handleEditClick = (cred) => {
    setEditingId(cred.id);
    setEditForm({
      site: cred.site,
      username: cred.username,
      password: cred.password,
      strength: cred.strength
    });
    setEditZxcvbnResult(zxcvbn(cred.password));
    setEditPasswordIdeas(buildStrongPasswordIdeas());
    setError("");
  };

  const handleEditChange = (e) => {
    const { name, value } = e.target;
    let updatedForm = { ...editForm, [name]: value };
    if (name === "password") {
      const result = zxcvbn(value);
      updatedForm.strength = getPasswordStrength(value);
      setEditZxcvbnResult(result);
    }
    setEditForm(updatedForm);
  };

  const handleEditSave = async (id) => {
    setError("");
    try {
      const res = await apiClient.put(`/credentials/${id}`, editForm);
      const updatedCredential = res.data?.credential || { ...editForm, id };
      setCredentials((current) =>
        current.map((cred) => (cred.id === id ? updatedCredential : cred))
      );
      setEditingId(null);
      setEditPasswordIdeas([]);
    } catch (err) {
      setError("Failed to update credential.");
    }
  };

  const handleEditCancel = () => {
    setEditingId(null);
    setEditPasswordIdeas([]);
    setError("");
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    let updatedForm = { ...form, [name]: value };
    if (name === "password") {
      const result = zxcvbn(value);
      updatedForm.strength = getPasswordStrength(value);
      setZxcvbnResult(result);
    }
    setForm(updatedForm);
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await apiClient.post("/credentials", form);
      if (res.data?.credential) {
        setCredentials((current) => [...current, res.data.credential]);
      }
      resetAddForm();
    } catch (err) {
      setError("Failed to add credential.");
    }
  };

  const resetAddForm = () => {
    setShowAdd(false);
    setForm({ site: "", username: "", password: "", strength: "medium" });
    setZxcvbnResult(zxcvbn(""));
    setPasswordIdeas([]);
    setError("");
    setShowAddPassword(false);
  };

  const applySuggestedPassword = (suggestedPassword) => {
    const result = zxcvbn(suggestedPassword);
    setForm((current) => ({
      ...current,
      password: suggestedPassword,
      strength: getPasswordStrength(suggestedPassword)
    }));
    setZxcvbnResult(result);
  };

  const applySuggestedEditPassword = (suggestedPassword) => {
    const result = zxcvbn(suggestedPassword);
    setEditForm((current) => ({
      ...current,
      password: suggestedPassword,
      strength: getPasswordStrength(suggestedPassword)
    }));
    setEditZxcvbnResult(result);
  };

  const aiSuggestions = useMemo(() => buildAiSuggestions(
    form.password,
    form.site,
    form.username,
    credentials,
    zxcvbnResult
  ), [form.password, form.site, form.username, credentials, zxcvbnResult]);

  const editAiSuggestions = useMemo(() => buildAiSuggestions(
    editForm.password,
    editForm.site,
    editForm.username,
    credentials.filter((cred) => cred.id !== editingId),
    editZxcvbnResult
  ), [editForm.password, editForm.site, editForm.username, credentials, editingId, editZxcvbnResult]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      <AnimatedBackground />
      <Navbar />
      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8 relative z-10">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-8 animate-fade-in">Password Vault</h2>
        <button
          className="mb-6 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all"
          onClick={() => {
            resetAddForm();
            setShowAdd(true);
          }}
        >
          Add Credential
        </button>
        {showAdd && (
          <form onSubmit={handleAdd} className="glass-card rounded-2xl p-6 mb-6 animate-fade-in">
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Site</label>
              <input name="site" value={form.site} onChange={handleChange} required className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all" />
            </div>
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Username</label>
              <input name="username" value={form.username} onChange={handleChange} required className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all" />
            </div>
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Password</label>
              <div className="relative">
                <input 
                  type={showAddPassword ? "text" : "password"}
                  name="password" 
                  value={form.password} 
                  onChange={handleChange} 
                  required 
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all pr-12" 
                />
                <button
                  type="button"
                  onClick={() => setShowAddPassword(!showAddPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  {showAddPassword ? (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="mt-2">
                <div className="w-full h-2 rounded bg-gray-700">
                  <div className={`h-2 rounded ${strengthColors[form.strength]}`} style={{ width: `${(zxcvbnResult.score + 1) * 20}%` }}></div>
                </div>
                <div className="text-xs text-white mt-1">
                  {zxcvbnResult.feedback.warning && <div className="text-yellow-300">{zxcvbnResult.feedback.warning}</div>}
                  {zxcvbnResult.feedback.suggestions && zxcvbnResult.feedback.suggestions.map((s, i) => (
                    <div key={i} className="text-blue-300">{s}</div>
                  ))}
                </div>
              </div>
              <div className="mt-4 rounded-xl border border-cyan-400/20 bg-slate-950/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] text-cyan-300/80">AI Upgrade Suggestions</div>
                    <div className="mt-1 text-sm text-white">{aiSuggestions.headline}</div>
                  </div>
                  {form.password && (
                    <button
                      type="button"
                      onClick={() => setPasswordIdeas(buildStrongPasswordIdeas())}
                      className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-200 transition-all hover:bg-cyan-500/20"
                    >
                      Refresh ideas
                    </button>
                  )}
                </div>
                {!!aiSuggestions.issues.length && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-rose-300">Risk signals</div>
                    <div className="mt-2 space-y-2 text-sm text-rose-100">
                      {aiSuggestions.issues.map((issue, index) => (
                        <div key={index} className="rounded-lg border border-rose-400/20 bg-rose-500/10 px-3 py-2">
                          {issue}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!!aiSuggestions.actions.length && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-amber-200">Recommended upgrades</div>
                    <div className="mt-2 space-y-2 text-sm text-slate-100">
                      {aiSuggestions.actions.map((action, index) => (
                        <div key={index} className="rounded-lg border border-amber-400/20 bg-amber-500/10 px-3 py-2">
                          {action}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!!aiSuggestions.positives.length && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-emerald-200">What already looks good</div>
                    <div className="mt-2 space-y-2 text-sm text-emerald-100">
                      {aiSuggestions.positives.map((positive, index) => (
                        <div key={index} className="rounded-lg border border-emerald-400/20 bg-emerald-500/10 px-3 py-2">
                          {positive}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!!passwordIdeas.length && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-cyan-200">One-click strong alternatives</div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {passwordIdeas.map((idea) => (
                        <button
                          key={idea}
                          type="button"
                          onClick={() => applySuggestedPassword(idea)}
                          className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-xs font-medium text-cyan-100 transition-all hover:bg-cyan-500/20"
                        >
                          Use {idea}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Strength</label>
              <span className={`px-2 py-1 rounded text-xs ${strengthColors[form.strength]}`}>{form.strength}</span>
            </div>
            {error && <div className="text-red-500 text-sm mb-4">{error}</div>}
            <button type="submit" className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all">Save</button>
            <button type="button" className="ml-3 bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all" onClick={resetAddForm}>Cancel</button>
          </form>
        )}
        <div className="glass-card rounded-2xl p-6 animate-fade-in overflow-x-auto">
          <table className="w-full text-white min-w-[800px]">
            <thead>
              <tr>
                <th className="text-left text-cyan-300 font-semibold pb-4">Site</th>
                <th className="text-left text-cyan-300 font-semibold pb-4">Username</th>
                <th className="text-left text-cyan-300 font-semibold pb-4">Password</th>
                <th className="text-left text-cyan-300 font-semibold pb-4">Strength</th>
                <th className="text-left text-cyan-300 font-semibold pb-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((cred) => (
                <tr key={cred.id} className="border-b border-white/10 hover:bg-white/5 transition-colors">
                  {editingId === cred.id ? (
                    <>
                      <td>
                        <input
                          name="site"
                          value={editForm.site}
                          onChange={handleEditChange}
                          className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all"
                        />
                      </td>
                      <td>
                        <input
                          name="username"
                          value={editForm.username}
                          onChange={handleEditChange}
                          className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all"
                        />
                      </td>
                      <td>
                        <div className="relative">
                          <input
                            type={showEditPassword[cred.id] ? "text" : "password"}
                            name="password"
                            value={editForm.password}
                            onChange={handleEditChange}
                            className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all pr-10"
                          />
                          <button
                            type="button"
                            onClick={() => setShowEditPassword({...showEditPassword, [cred.id]: !showEditPassword[cred.id]})}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-cyan-400 hover:text-cyan-300 transition-colors"
                          >
                            {showEditPassword[cred.id] ? (
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                              </svg>
                            ) : (
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                              </svg>
                            )}
                          </button>
                        </div>
                        <div className="mt-1">
                          <div className="w-full h-1 rounded bg-gray-700">
                            <div className={`h-1 rounded ${strengthColors[editForm.strength]}`} style={{ width: `${(editZxcvbnResult.score + 1) * 20}%` }}></div>
                          </div>
                        </div>
                        <div className="mt-3 rounded-xl border border-cyan-400/20 bg-slate-950/40 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-[10px] uppercase tracking-[0.2em] text-cyan-300/80">AI Upgrade Suggestions</div>
                              <div className="mt-1 text-xs text-white">{editAiSuggestions.headline}</div>
                            </div>
                            {editForm.password && (
                              <button
                                type="button"
                                onClick={() => setEditPasswordIdeas(buildStrongPasswordIdeas())}
                                className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2 py-1 text-[10px] font-semibold text-cyan-200 transition-all hover:bg-cyan-500/20"
                              >
                                Refresh
                              </button>
                            )}
                          </div>
                          {!!editAiSuggestions.issues.length && (
                            <div className="mt-3 space-y-2">
                              {editAiSuggestions.issues.map((issue, index) => (
                                <div key={index} className="rounded-lg border border-rose-400/20 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">
                                  {issue}
                                </div>
                              ))}
                            </div>
                          )}
                          {!!editAiSuggestions.actions.length && (
                            <div className="mt-3 space-y-2">
                              {editAiSuggestions.actions.map((action, index) => (
                                <div key={index} className="rounded-lg border border-amber-400/20 bg-amber-500/10 px-3 py-2 text-xs text-slate-100">
                                  {action}
                                </div>
                              ))}
                            </div>
                          )}
                          {!!editAiSuggestions.positives.length && (
                            <div className="mt-3 space-y-2">
                              {editAiSuggestions.positives.map((positive, index) => (
                                <div key={index} className="rounded-lg border border-emerald-400/20 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100">
                                  {positive}
                                </div>
                              ))}
                            </div>
                          )}
                          {!!editPasswordIdeas.length && (
                            <div className="mt-3 flex flex-wrap gap-2">
                              {editPasswordIdeas.map((idea) => (
                                <button
                                  key={idea}
                                  type="button"
                                  onClick={() => applySuggestedEditPassword(idea)}
                                  className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-[10px] font-medium text-cyan-100 transition-all hover:bg-cyan-500/20"
                                >
                                  Use {idea}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`px-2 py-1 rounded text-xs ${strengthColors[editForm.strength]}`}>{editForm.strength}</span>
                      </td>
                      <td>
                        <button
                          className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-3 py-2 rounded-lg btn-futuristic shadow-md transition-all mr-2"
                          onClick={() => handleEditSave(cred.id)}
                        >
                          Save
                        </button>
                        <button
                          className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-3 py-2 rounded-lg btn-futuristic shadow-md transition-all"
                          onClick={handleEditCancel}
                        >
                          Cancel
                        </button>
                      </td>
                    </>
                  ) : (
                    <>
                      <td>{cred.site}</td>
                      <td>{cred.username}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span>{showPassword[cred.id] ? cred.password : "•".repeat(cred.password.length)}</span>
                          <button
                            onClick={() => setShowPassword({...showPassword, [cred.id]: !showPassword[cred.id]})}
                            className="text-cyan-400 hover:text-cyan-300 transition-colors"
                          >
                            {showPassword[cred.id] ? (
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                              </svg>
                            ) : (
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                              </svg>
                            )}
                          </button>
                        </div>
                      </td>
                      <td>
                        <span className={`px-2 py-1 rounded text-xs ${cred.strength === "strong" ? "bg-green-600" : cred.strength === "medium" ? "bg-yellow-600" : "bg-red-600"}`}>{cred.strength}</span>
                      </td>
                      <td>
                        <button
                          className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-3 py-2 rounded-lg btn-futuristic shadow-md transition-all mr-2"
                          onClick={() => handleEditClick(cred)}
                        >
                          Edit
                        </button>
                        <button
                          className="bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 text-white px-3 py-2 rounded-lg btn-futuristic shadow-md transition-all"
                          onClick={() => handleRemove(cred.id)}
                          disabled={removingId === cred.id}
                        >
                          {removingId === cred.id ? "Removing..." : "Remove"}
                        </button>
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default VaultPage;
