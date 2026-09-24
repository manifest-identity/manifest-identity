"use strict";
// The one rule this file exists to keep: every value from the API
// reaches the page through textContent or a text node, never through
// innerHTML. Imported files control identity names, tags, and policy
// text, so all of it is untrusted, and this page has no markup sink
// that attacker-influenced strings can reach. The token lives in a
// closure variable, never in localStorage, so it does not survive a
// tab close and is not readable by injected script from another origin.

let token = null;
let currentUser = null;
let currentRole = null;
let currentRoles = [];
let detailId = null;
let selectedGroup = null;

const $ = (id) => document.getElementById(id);
const show = (id) => $(id).hidden = false;
const hide = (id) => $(id).hidden = true;

// The theme is a browser preference, stored locally and never sent
// anywhere: the server has no idea which mode anyone reads in.
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("theme-toggle").textContent = theme === "dark" ? "day mode" : "night mode";
  try { localStorage.setItem("manifest-identity-theme", theme); } catch { /* private mode */ }
}
$("theme-toggle").addEventListener("click", () => {
  const current = document.documentElement.dataset.theme === "dark";
  applyTheme(current ? "light" : "dark");
});
try {
  const saved = localStorage.getItem("manifest-identity-theme");
  if (saved === "dark") applyTheme("dark");
} catch { /* private mode keeps the default */ }

// Build one table row from a spec of plain-text cells. Numbers and
// strings only; nothing here parses HTML.
function row(cells, onClick) {
  const tr = document.createElement("tr");
  for (const cell of cells) {
    const td = document.createElement("td");
    td.textContent = String(cell);
    tr.appendChild(td);
  }
  if (onClick) {
    tr.classList.add("clickable");
    tr.addEventListener("click", onClick);
  }
  return tr;
}

function tile(label, value, kind) {
  const div = document.createElement("div");
  div.className = "tile " + (kind || "");
  const v = document.createElement("span");
  v.className = "tile-value";
  v.textContent = String(value);
  const l = document.createElement("span");
  l.className = "tile-label";
  l.textContent = label;
  div.append(v, l);
  return div;
}

async function api(path, options) {
  const opts = options || {};
  opts.headers = { ...opts.headers };
  if (token) opts.headers["Authorization"] = "Bearer " + token;
  const response = await fetch(path, opts);
  if (response.status === 401) {
    signOut();
    throw new Error("session ended");
  }
  return response;
}

async function signIn(username, password) {
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("invalid credentials");
  const body = await response.json();
  token = body.token;
  currentUser = username;
  // The highest role the user holds anywhere drives what the page
  // offers; the full set is shown beside the name, because a user
  // bound as an operator in one place and a reviewer in another is
  // now an ordinary case (D-072).
  currentRole = body.role;
  currentRoles = body.roles || [body.role];
  return body.role;
}

const VIEWS = [
  "inventory", "detail", "groups", "campaigns", "campaign-detail", "imports",
  "scopes", "delta",
];

function signOut() {
  if (token) api("/auth/logout", { method: "POST" }).catch(() => {});
  token = null;
  currentUser = null;
  currentRole = null;
  currentRoles = [];
  detailId = null;
  selectedGroup = null;
  for (const id of VIEWS) hide(id);
  hide("nav");
  hide("asof");
  show("signin");
}

function switchView(view) {
  for (const id of VIEWS) hide(id);
  show(view);
}

// Downloads carry the session header, so they go through fetch and a
// temporary object URL rather than a plain link the token cannot ride.
async function download(path, filename) {
  const response = await api(path);
  if (!response.ok) return;
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Paging state for the inventory: the server filters and slices, the
// browser only remembers where it is (issue 38).
const PAGE_SIZE = 100;
let pageOffset = 0;

// Sorting is the server's job over the whole matched set; the header
// only remembers which column and direction were asked for.
let sortKey = null;
let sortDir = "asc";

function paintSortMarkers() {
  for (const th of document.querySelectorAll("#inventory-head th[data-sort]")) {
    if (!th.dataset.label) th.dataset.label = th.textContent;
    const active = th.dataset.sort === sortKey;
    let marker = "";
    if (active) marker = sortDir === "asc" ? " ▴" : " ▾";
    th.textContent = th.dataset.label + marker;
    if (active) th.setAttribute("aria-sort", sortDir === "asc" ? "ascending" : "descending");
    else th.removeAttribute("aria-sort");
  }
}

async function loadInventory() {
  switchView("inventory");
  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(pageOffset),
  });
  const text = $("filter-text").value.trim();
  const type = $("filter-type").value;
  const tier = $("filter-tier").value;
  const kind = $("filter-kind").value;
  if (text) params.set("q", text);
  if (type) params.set("type", type);
  if (tier) params.set("tier", tier);
  if (kind) params.set("kind", kind);
  if (sortKey) { params.set("sort", sortKey); params.set("direction", sortDir); }
  paintSortMarkers();
  const page = await (await api("/identities?" + params)).json();
  const dash = $("dashboard");
  dash.replaceChildren(
    tile("identities", page.tiles.identities),
    tile("critical", page.tiles.critical, "critical"),
    tile("warning", page.tiles.warning, "warning"),
    tile("notice", page.tiles.notice, "notice"),
    tile("quiet", page.tiles.quiet, "quiet"),
  );
  renderIdentities(page.rows);
  const from = page.matched === 0 ? 0 : page.offset + 1;
  const to = page.offset + page.rows.length;
  $("page-status").textContent = from + " to " + to + " of " + page.matched;
  $("page-prev").disabled = page.offset === 0;
  $("page-next").disabled = to >= page.matched;
}

function identityTier(r) {
  if (r.critical) return "critical";
  if (r.warning) return "warning";
  if (r.notice) return "notice";
  return "quiet";
}

function renderIdentities(rows) {
  const tbody = $("identity-rows");
  tbody.replaceChildren();
  $("inventory-empty").hidden = rows.length !== 0;
  for (const r of rows) {
    const flags = [
      r.name_reused ? "name reused" : "",
      r.flagged ? "flagged" : "",
    ].filter(Boolean).join(", ");
    const tr = row(
      [r.display_name, r.identity_type, r.kind, r.account,
       r.critical, r.warning, r.notice, r.top_finding || "", flags],
      () => loadDetail(r.id),
    );
    tr.classList.add("tier-" + identityTier(r));
    tbody.appendChild(tr);
  }
}

function fact(dl, label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value === null || value === undefined ? "unknown" : String(value);
  dl.append(dt, dd);
}

// "platform-team (team, assigned)" or "sre (tag)"; a tag owner is a
// string with no claim about what kind of thing the string names.
function ownerDescription(d) {
  if (!d.owner) return "unowned";
  const bits = [d.owner_type, d.owner_source]
    .filter(Boolean)
    .map((b) => b.replace("_", " "))
    .join(", ");
  return bits ? d.owner + " (" + bits + ")" : d.owner;
}

async function loadDetail(id) {
  const d = await (await api("/identities/" + id)).json();
  detailId = id;
  switchView("detail");
  $("detail-name").textContent = d.display_name + "  (" + d.identity_type + ")";
  const facts = $("detail-facts");
  facts.replaceChildren();
  fact(facts, "account", d.account);
  fact(facts, "kind", d.kind + " (" + d.kind_reason + ")");
  fact(facts, "owner", ownerDescription(d));
  fact(facts, "provisional", d.provisional);
  fact(facts, "name reused", d.name_reused);
  fact(facts, "as of", d.as_of);
  fact(facts, "observed days", d.observed_days);
  fact(facts, "last activity", d.last_activity);

  const findings = $("detail-findings");
  findings.replaceChildren();
  if (!d.findings.length) {
    const li = document.createElement("li");
    li.textContent = "no findings";
    findings.appendChild(li);
  }
  for (const f of d.findings) {
    const li = document.createElement("li");
    li.className = "finding tier-" + f.tier;
    const tag = document.createElement("span");
    tag.className = "finding-tier";
    tag.textContent = f.tier + " / " + f.anchor;
    const body = document.createElement("span");
    body.textContent = f.explanation;
    li.append(tag, body);
    findings.appendChild(li);
  }

  const sources = $("detail-sources");
  sources.replaceChildren();
  if (!d.privilege_sources.length) {
    const li = document.createElement("li");
    li.textContent = "no privilege sources";
    sources.appendChild(li);
  }
  for (const s of d.privilege_sources) {
    const li = document.createElement("li");
    li.textContent = s;
    sources.appendChild(li);
  }

  renderDetailGovernance(d);
  await renderAuthorizations(id);

  const timeline = $("detail-timeline");
  timeline.replaceChildren();
  for (const o of d.timeline) {
    timeline.appendChild(row([o.captured_at, o.source, o.fields_present]));
  }
}

// One list item per governance record: the statement, its author, and
// for the roles that may, a clear button. Everything is a text node.
function governanceItem(r, onCleared) {
  const li = document.createElement("li");
  const text = document.createElement("span");
  text.textContent = r.kind + ": " + r.value
    + (r.owner_type ? " (" + r.owner_type.replace("_", " ") + ")" : "")
    + ", set by " + r.actor + " on " + r.created_at;
  li.appendChild(text);
  if (currentRole !== "reviewer") {
    const clear = document.createElement("button");
    clear.type = "button";
    clear.textContent = "clear";
    clear.addEventListener("click", async () => {
      await api("/governance/" + r.id, { method: "DELETE" });
      onCleared();
    });
    li.append(" ", clear);
  }
  return li;
}

// What is authorized, and the chain behind it. Read for every role;
// written by the operator and the administrator, matching the matrix.
async function renderAuthorizations(id) {
  const rows = await (await api("/identities/" + id + "/authorizations")).json();
  const superseded = new Set(
    rows.map((r) => r.supersedes_id).filter((x) => x !== null));
  const live = rows.filter(
    (r) => r.status === "authorized" && !superseded.has(r.id));
  const active = $("auth-active");
  active.replaceChildren();
  $("auth-empty").hidden = live.length > 0;
  for (const r of live) {
    const li = document.createElement("li");
    const hops = r.path.map(
      (h) => h.via + (h.ref ? " " + h.ref : "")).join(" then ");
    li.appendChild(document.createTextNode(
      r.role_definition_external_id + ", " + r.mode + ", by " + hops
      + ", owned by " + r.owner_ref
      + (r.valid_until ? ", until " + r.valid_until.slice(0, 10) : ", no expiry")
      + ", authorized by " + r.authorizer));
    if (currentRole !== "reviewer") {
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "revoke";
      revoke.addEventListener("click", async () => {
        // A revocation says why, so the record explains itself; the
        // server refuses an empty reason and so does this.
        const reason = window.prompt("Why is this being revoked?");
        if (!reason || !reason.trim()) return;
        const response = await api("/authorizations/" + r.id + "/revoke", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason }),
        });
        if (response.ok) loadDetail(id);
      });
      li.append(" ", revoke);
    }
    active.appendChild(li);
  }
  $("auth-form").hidden = currentRole === "reviewer";
  $("auth-result").hidden = true;
  const history = $("auth-history");
  history.replaceChildren();
  for (const r of rows) {
    history.appendChild(row([
      r.role_definition_external_id, r.mode, r.owner_ref, r.status,
      r.authorizer, r.authorized_at,
      r.valid_until ? r.valid_until.slice(0, 10) : "",
    ]));
  }
}

function renderDetailGovernance(d) {
  const active = $("gov-active");
  active.replaceChildren();
  const activeRecords = d.governance.filter((r) => !r.cleared_at);
  if (!activeRecords.length) {
    const li = document.createElement("li");
    li.textContent = "no governance records";
    active.appendChild(li);
  }
  for (const r of activeRecords) {
    active.appendChild(governanceItem(r, () => loadDetail(d.id)));
  }
  // Reviewers attest; changing owner, purpose, or flag is the
  // operator's act, matching the route matrix.
  $("gov-form").hidden = currentRole === "reviewer";
  $("gov-result").hidden = true;
  const history = $("gov-history");
  history.replaceChildren();
  for (const r of d.governance) {
    history.appendChild(row([
      r.kind, r.value, r.actor, r.created_at,
      r.cleared_at || "", r.cleared_by || "",
    ]));
  }
}

function detailText(detail) {
  if (Array.isArray(detail)) {
    return detail.map((entry) => String(entry.msg || "")).join("; ");
  }
  return String(detail);
}

async function submitGovernance(path, payload, resultId, reload) {
  const result = $(resultId);
  result.hidden = false;
  result.textContent = "saving...";
  try {
    const response = await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      result.hidden = true;
      reload();
    } else {
      const data = await response.json();
      result.textContent = "rejected: " + detailText(data.detail);
    }
  } catch {
    result.textContent = "the change could not be saved";
  }
}

async function loadGroups() {
  switchView("groups");
  selectedGroup = null;
  hide("group-gov-title");
  $("group-gov-form").hidden = true;
  $("group-gov-active").replaceChildren();
  $("group-gov-result").hidden = true;
  const rows = await (await api("/groups")).json();
  window._groups = rows;
  const tbody = $("group-rows");
  tbody.replaceChildren();
  $("groups-empty").hidden = rows.length !== 0;
  for (const g of rows) {
    const summary = g.findings.map((f) => f.code).join(", ") || "none";
    tbody.appendChild(row(
      [g.name, g.account, g.members, g.privileged ? "yes" : "no",
       g.owner || "unowned", g.flagged ? "flagged" : "", summary],
      g.id === null ? undefined : () => selectGroup(g)));
  }
}

async function reloadGroupsKeepSelection(id) {
  await loadGroups();
  const g = (window._groups || []).find((x) => x.id === id);
  if (g) selectGroup(g);
}

function selectGroup(g) {
  selectedGroup = g;
  const title = $("group-gov-title");
  title.textContent = "Governance: " + g.name;
  title.hidden = false;
  const active = $("group-gov-active");
  active.replaceChildren();
  const records = g.governance.filter((r) => !r.cleared_at);
  if (!records.length) {
    const li = document.createElement("li");
    li.textContent = "no governance records";
    active.appendChild(li);
  }
  for (const r of records) {
    active.appendChild(governanceItem(r, () => reloadGroupsKeepSelection(g.id)));
  }
  const form = $("group-gov-form");
  form.hidden = false;
  const kind = form.querySelector('[name="kind"]');
  for (const option of kind.options) {
    option.hidden = currentRole === "reviewer" && option.value !== "attestation";
  }
  if (currentRole === "reviewer") kind.value = "attestation";
  kind.dispatchEvent(new Event("change"));
}

// The delta, grouped by what is wrong: the tile is the count and the
// table is the detail, so a reader starts from the class that matters
// rather than from an alphabet of identities.
async function loadDelta() {
  switchView("delta");
  const body = await (await api("/delta")).json();
  const tiles = $("delta-tiles");
  tiles.replaceChildren();
  let total = 0;
  for (const [kind, count] of Object.entries(body.counts)) {
    total += count;
    tiles.appendChild(tile(body.titles[kind], count, kind));
  }
  $("delta-empty").hidden = total > 0;
  const rows = $("delta-rows");
  rows.replaceChildren();
  for (const f of body.findings) {
    const hops = f.path.map(
      (h) => h.via + (h.ref ? " " + h.ref : "")).join(" then ");
    rows.appendChild(row([
      f.title, f.account, f.display_name, f.role, hops, f.detail,
      f.observed_as_of || "never", f.authorized_as_of || "never",
    ], () => loadDetail(f.identity_id)));
  }
}

async function loadScopes() {
  switchView("scopes");
  const rows = await (await api("/admin/scopes")).json();
  const names = new Map(rows.map((n) => [n.id, n.display_name]));
  const tbody = $("scope-rows");
  tbody.replaceChildren();
  for (const n of rows) {
    tbody.appendChild(row([
      n.provider, n.partition, n.kind, n.external_id, n.display_name,
      n.parent_id === null ? "" : (names.get(n.parent_id) || n.parent_id),
    ]));
  }
}

async function loadImports() {
  switchView("imports");
  const rows = await (await api("/imports")).json();
  const tbody = $("import-rows");
  tbody.replaceChildren();
  for (const s of rows) {
    tbody.appendChild(row(
      [s.account, s.source, s.captured_at, s.imported_at, s.row_count, s.skipped_count]));
  }
}

async function refreshAsOf() {
  const rows = await (await api("/imports")).json();
  const el = $("asof");
  if (!rows.length) { hide("asof"); return; }
  const newest = rows.map((s) => s.captured_at).sort().at(-1);
  el.textContent = "inventory as of " + newest;
  show("asof");
}

function enterApp(role) {
  hide("signin");
  show("nav");
  $("whoami").textContent =
    currentUser + " (" + currentRoles.join(", ") + ")";
  // The scope tree is read through an administrative route, so the
  // button only appears for the role that may call it.
  $("nav-scopes").hidden = !currentRoles.includes("administrator");
  refreshAsOf();
  loadInventory();
}

$("signin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const err = $("signin-error");
  err.hidden = true;
  try {
    const role = await signIn(form.get("username"), form.get("password"));
    e.target.reset();
    enterApp(role);
  } catch {
    // The server's generic message, never echoed input.
    err.textContent = "Sign in failed.";
    err.hidden = false;
  }
});

async function loadCampaigns() {
  switchView("campaigns");
  $("campaign-form").hidden = currentRole === "reviewer";
  $("campaign-result").hidden = true;
  const rows = await (await api("/campaigns")).json();
  const tbody = $("campaign-rows");
  tbody.replaceChildren();
  $("campaigns-empty").hidden = rows.length !== 0;
  for (const c of rows) {
    tbody.appendChild(row(
      [c.name, c.scope, c.due_at, c.disposed + " of " + c.total,
       c.recurrence, c.closed_at ? "closed" : "open"],
      () => loadCampaignDetail(c.id)));
  }
  const rollup = await (await api("/campaigns/rollup")).json();
  const rtbody = $("rollup-rows");
  rtbody.replaceChildren();
  if (!rollup.length) {
    rtbody.appendChild(row(["none recorded", "", "", "", ""]));
  }
  for (const entry of rollup) {
    rtbody.appendChild(row([
      entry.campaign, entry.display_name, entry.note,
      entry.disposed_by, entry.disposed_at,
    ]));
  }
}

// One card per item: the recommendation with its reasons, the delta
// since the last certification, and either the decision that was made
// or the controls to make one. One item, one decision, no bulk path.
function itemCard(campaign, item) {
  const card = document.createElement("div");
  card.className = "finding";
  const title = document.createElement("span");
  title.className = "finding-tier";
  title.textContent = item.display_name + " (" + item.target_type + ") "
    + "recommendation: " + item.recommendation.replaceAll("_", " ");
  card.appendChild(title);

  const reasons = document.createElement("ul");
  for (const reason of item.recommendation_reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasons.appendChild(li);
  }
  card.appendChild(reasons);

  if (item.delta.length) {
    const heading = document.createElement("span");
    heading.className = "finding-tier";
    heading.textContent = "changed since last certification";
    card.appendChild(heading);
    const delta = document.createElement("ul");
    for (const line of item.delta) {
      const li = document.createElement("li");
      li.textContent = line;
      delta.appendChild(li);
    }
    card.appendChild(delta);
  }

  if (item.disposition) {
    const decided = document.createElement("p");
    decided.textContent = "decided: " + item.disposition.replaceAll("_", " ")
      + (item.disposition_note ? " (" + item.disposition_note + ")" : "")
      + ", by " + item.disposed_by + " on " + item.disposed_at;
    card.appendChild(decided);
    return card;
  }
  if (campaign.closed_at) return card;

  const note = document.createElement("input");
  note.placeholder = "note (what was missing, or who holds it)";
  note.maxLength = 500;
  note.className = "disposition-note";
  card.appendChild(note);
  const actions = document.createElement("div");
  for (const disposition of [
    "certify", "revoke_recommended", "insufficient_evidence", "delegated",
  ]) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = disposition.replaceAll("_", " ");
    button.addEventListener("click", async () => {
      const body = { disposition };
      if (note.value.trim()) body.note = note.value.trim();
      const result = $("campaign-detail-result");
      const response = await api(
        "/campaigns/" + campaign.id + "/items/" + item.id + "/disposition",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      if (response.ok) {
        result.hidden = true;
        loadCampaignDetail(campaign.id);
      } else {
        const data = await response.json();
        result.textContent = "rejected: " + detailText(data.detail);
        result.hidden = false;
      }
    });
    actions.appendChild(button);
  }
  card.appendChild(actions);
  return card;
}

async function loadCampaignDetail(id) {
  const c = await (await api("/campaigns/" + id)).json();
  switchView("campaign-detail");
  $("campaign-name").textContent = c.name;
  $("campaign-facts").textContent = "scope " + c.scope + ", due " + c.due_at
    + ", " + c.disposed + " of " + c.total + " decided"
    + (c.closed_at ? ", closed by " + c.closed_by + " on " + c.closed_at
       : ", open")
    + (c.next_due ? ", next cycle due " + c.next_due : "");
  $("campaign-detail-result").hidden = true;
  const close = $("campaign-close");
  close.hidden = currentRole === "reviewer" || c.closed_at !== null;
  close.onclick = async () => {
    const response = await api("/campaigns/" + c.id + "/close",
                               { method: "POST" });
    if (response.ok) loadCampaignDetail(c.id);
    else {
      const data = await response.json();
      const result = $("campaign-detail-result");
      result.textContent = "rejected: " + detailText(data.detail);
      result.hidden = false;
    }
  };
  $("campaign-evidence").onclick = () =>
    download("/campaigns/" + c.id + "/evidence",
             "campaign-" + c.id + "-evidence.json");
  const items = $("campaign-items");
  items.replaceChildren();
  for (const item of c.items) items.appendChild(itemCard(c, item));
}

$("campaign-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const result = $("campaign-result");
  const response = await api("/campaigns", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: form.get("name"),
      scope: form.get("scope"),
      due_at: form.get("due_at"),
      recurrence: form.get("recurrence"),
    }),
  });
  if (response.ok) {
    result.hidden = true;
    e.target.reset();
    loadCampaigns();
  } else {
    const data = await response.json();
    result.textContent = "rejected: " + detailText(data.detail);
    result.hidden = false;
  }
});

$("campaign-back").addEventListener("click", loadCampaigns);
$("campaign-x").addEventListener("click", loadCampaigns);
$("download-report").addEventListener("click",
  () => download("/report.html", "manifest-identity-report.html"));
$("download-csv").addEventListener("click",
  () => download("/export.csv", "manifest-identity.csv"));
$("download-json").addEventListener("click",
  () => download("/export.json", "manifest-identity.json"));

$("nav").addEventListener("click", (e) => {
  const view = e.target.dataset.view;
  if (view === "inventory") loadInventory();
  else if (view === "groups") loadGroups();
  else if (view === "campaigns") loadCampaigns();
  else if (view === "imports") loadImports();
  else if (view === "scopes") loadScopes();
  else if (view === "delta") loadDelta();
});
$("signout").addEventListener("click", signOut);
$("back").addEventListener("click", loadInventory);
// A filter change is a new question, so it starts at the first page;
// the text input waits a beat so a keystroke run is one request.
let filterTimer = null;
function filtersChanged(delayed) {
  pageOffset = 0;
  clearTimeout(filterTimer);
  if (delayed) filterTimer = setTimeout(loadInventory, 250);
  else loadInventory();
}
$("inventory-head").addEventListener("click", (e) => {
  const th = e.target.closest("th[data-sort]");
  if (!th) return;
  const key = th.dataset.sort;
  if (sortKey === key) sortDir = sortDir === "asc" ? "desc" : "asc";
  else { sortKey = key; sortDir = "asc"; }
  pageOffset = 0;  // a new order is a new question, so page one
  loadInventory();
});
$("filter-text").addEventListener("input", () => filtersChanged(true));
$("filter-type").addEventListener("input", () => filtersChanged(false));
$("filter-tier").addEventListener("input", () => filtersChanged(false));
$("filter-kind").addEventListener("input", () => filtersChanged(false));
$("page-prev").addEventListener("click", () => {
  pageOffset = Math.max(0, pageOffset - PAGE_SIZE);
  loadInventory();
});
$("page-next").addEventListener("click", () => {
  pageOffset += PAGE_SIZE;
  loadInventory();
});

// The owner type only means something on an owner record; the routes
// refuse it elsewhere, and the form does not offer it elsewhere.
function wireOwnerTypeVisibility(formId) {
  const form = $(formId);
  const kind = form.querySelector('[name="kind"]');
  const ownerLabel = form.querySelector('[name="owner_type"]').closest("label");
  const sync = () => { ownerLabel.hidden = kind.value !== "owner"; };
  kind.addEventListener("change", sync);
  sync();
}
// The second owner is required only when a person owns it, and the
// group name is asked for only when access arrives through one: the
// form offers what the rule needs and nothing else.
(function wireAuthorizationForm() {
  const form = $("auth-form");
  const via = form.querySelector('[name="via"]');
  const ownerKind = form.querySelector('[name="owner_kind"]');
  const sync = () => {
    $("auth-ref-label").hidden = via.value === "direct";
    $("auth-secondary").hidden = ownerKind.value !== "individual";
  };
  via.addEventListener("change", sync);
  ownerKind.addEventListener("change", sync);
  sync();
})();

$("auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const via = form.get("via");
  const payload = {
    role_definition_external_id: form.get("role_definition_external_id"),
    path: [{ via, ref: via === "direct" ? "" : (form.get("ref") || ""),
             mode: "active" }],
    mode: form.get("mode"),
    owner_kind: form.get("owner_kind"),
    owner_ref: form.get("owner_ref"),
  };
  if (form.get("owner_kind") === "individual") {
    payload.secondary_owner_kind = form.get("secondary_owner_kind");
    payload.secondary_owner_ref = form.get("secondary_owner_ref");
  }
  for (const name of ["justification", "reference", "control_reference"]) {
    if (form.get(name)) payload[name] = form.get(name);
  }
  // A date input gives a day; the record keeps an instant, and the
  // end of that day is what a person means by "until".
  if (form.get("valid_until")) {
    payload.valid_until = form.get("valid_until") + "T23:59:59+00:00";
  }
  const result = $("auth-result");
  result.hidden = false;
  result.textContent = "saving...";
  try {
    const response = await api(
      "/identities/" + detailId + "/authorizations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    if (response.ok) {
      result.hidden = true;
      e.target.reset();
      loadDetail(detailId);
    } else {
      const data = await response.json();
      result.textContent = "refused: " + detailText(data.detail);
    }
  } catch {
    result.textContent = "the authorization could not be saved";
  }
});

wireOwnerTypeVisibility("gov-form");
wireOwnerTypeVisibility("group-gov-form");

$("gov-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const kind = form.get("kind");
  const payload = { kind, value: form.get("value") };
  if (kind === "owner") payload.owner_type = form.get("owner_type");
  await submitGovernance(
    "/identities/" + detailId + "/governance", payload, "gov-result",
    () => loadDetail(detailId));
  e.target.querySelector('[name="value"]').value = "";
});

$("attest-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  await submitGovernance(
    "/identities/" + detailId + "/attest", { value: form.get("value") },
    "gov-result", () => loadDetail(detailId));
});

$("group-gov-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedGroup) return;
  const form = new FormData(e.target);
  const kind = form.get("kind");
  const id = selectedGroup.id;
  const path = kind === "attestation"
    ? "/groups/" + id + "/attest"
    : "/groups/" + id + "/governance";
  const payload = kind === "attestation"
    ? { value: form.get("value") }
    : { kind, value: form.get("value") };
  if (kind === "owner") payload.owner_type = form.get("owner_type");
  await submitGovernance(path, payload, "group-gov-result",
    () => reloadGroupsKeepSelection(id));
  e.target.querySelector('[name="value"]').value = "";
});

$("import-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const kind = form.get("kind");
  const body = new FormData();
  body.append("file", form.get("file"));
  body.append("captured_at", form.get("captured_at"));
  const result = $("import-result");
  result.hidden = false;
  result.textContent = "importing...";
  try {
    const response = await api("/imports/" + encodeURIComponent(kind), { method: "POST", body });
    const data = await response.json();
    if (response.ok) {
      result.textContent = "imported " + data.observations + " observations, "
        + data.identities_new + " new, " + data.skipped_rows + " skipped";
      e.target.reset();
      loadImports();
      refreshAsOf();
    } else {
      // The server's message states a rule; it never contains file text.
      result.textContent = "rejected: " + data.detail;
    }
  } catch {
    result.textContent = "the import could not be completed";
  }
});
