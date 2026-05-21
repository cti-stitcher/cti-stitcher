/**
 * cti-stitcher shared JS utilities
 */

const API = {
  async get(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  },
  async post(path, body = {}) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  },
};

function countryFlag(code) {
  if (!code) return "";
  const COUNTRY_FLAGS = {
    CN: "🇨🇳", RU: "🇷🇺", KP: "🇰🇵", IR: "🇮🇷",
    VN: "🇻🇳", IN: "🇮🇳", PK: "🇵🇰", TR: "🇹🇷",
    UA: "🇺🇦", IL: "🇮🇱", US: "🇺🇸",
  };
  return COUNTRY_FLAGS[code] || code;
}

function countryName(code) {
  const NAMES = {
    CN: "China", RU: "Russia", KP: "North Korea", IR: "Iran",
    VN: "Vietnam", IN: "India", PK: "Pakistan", TR: "Turkey",
    UA: "Ukraine", IL: "Israel", US: "United States",
  };
  return NAMES[code] || code || "Unknown";
}

function confidenceBadge(conf) {
  const cls = { high: "tag-success", medium: "tag-warn", low: "" }[conf] || "";
  return `<span class="tag ${cls}">${conf}</span>`;
}

function tag(text, cls = "") {
  return `<span class="tag ${cls}">${text}</span>`;
}

async function loadSyncStatus(el) {
  try {
    const statuses = await API.get("/api/sync/status");
    const last = statuses
      .filter(s => s.last_run)
      .sort((a, b) => new Date(b.last_run) - new Date(a.last_run))[0];
    if (last && el) {
      const d = new Date(last.last_run);
      el.textContent = `Last synced: ${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
    } else if (el) {
      el.textContent = "Not yet synced";
    }
  } catch (e) {
    if (el) el.textContent = "";
  }
}

// Mark active nav link
document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;
  document.querySelectorAll(".topbar-nav a").forEach(a => {
    if (a.getAttribute("href") === path || (path === "/" && a.getAttribute("href") === "/")) {
      a.classList.add("active");
    }
  });
});
