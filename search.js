"use strict";

// Ranked search over vault metadata for the desktop search box and Quick Access.
// It reads names, usernames, URLs and notes only; values never enter the results.

const FIELD_WEIGHTS = {
    key: 1,
    project: 0.6,
    provider: 0.5,
    username: 0.5,
    email: 0.5,
    host: 0.5,
    note: 0.3
};

const EXACT = 100, PREFIX = 60, WORD = 40, SUBSTRING = 25, FUZZY = 10;

const BOUNDARY = /[\s_\-./@:]/;

function hostOf(url) {
    if (!url) return "";
    try {
        return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname;
    } catch {
        return "";
    }
}

// How well one lower-case token matches one lower-case field value.
function matchScore(value, token, allowFuzzy) {
    if (!value) return 0;
    if (value === token) return EXACT;
    if (value.startsWith(token)) return PREFIX;
    let at = value.indexOf(token);
    if (at > 0) {
        while (at !== -1) {
            if (BOUNDARY.test(value[at - 1])) return WORD;
            at = value.indexOf(token, at + 1);
        }
        return SUBSTRING;
    }
    if (!allowFuzzy || token.length < 2) return 0;
    // Subsequence match ("stsk" finds STRIPE_SECRET_KEY), penalised by the gaps it skips.
    let i = 0, gaps = 0, last = -1;
    for (let j = 0; j < value.length && i < token.length; j++) {
        if (value[j] === token[i]) {
            if (last !== -1 && j !== last + 1) gaps++;
            last = j;
            i++;
        }
    }
    return i === token.length ? Math.max(1, FUZZY - gaps) : 0;
}

function itemFields(project, s) {
    return {
        key: String(s.key || "").toLowerCase(),
        project: String(project.name || "").toLowerCase(),
        provider: String(s.provider || "").toLowerCase(),
        username: String(s.username || "").toLowerCase(),
        email: String(s.email || "").toLowerCase(),
        host: hostOf(String(s.url || "")).toLowerCase(),
        note: String(s.note || "").toLowerCase()
    };
}

function result(project, s, score) {
    return {
        project: project.name,
        key: s.key,
        provider: s.provider || "",
        username: s.username || "",
        email: s.email || "",
        url: s.url || "",
        host: hostOf(s.url || ""),
        hasValue: !!(s.value || s.password),
        expiresAt: s.expiresAt || "",
        injectApproved: s.injectApproved !== false,
        updatedAt: s.updatedAt || "",
        score: score
    };
}

// Every whitespace-separated token must match some field. A token's score is its best
// weighted field match; the item's score is the sum. An empty query lists recent changes.
function searchItems(projects, query, {limit: limit = 50} = {}) {
    const tokens = String(query || "").toLowerCase().trim().split(/\s+/).filter(Boolean).slice(0, 8);
    const out = [];
    for (const project of projects || []) {
        for (const s of project.secrets || []) {
            if (!tokens.length) {
                out.push(result(project, s, 0));
                continue;
            }
            const fields = itemFields(project, s);
            let total = 0;
            for (const token of tokens) {
                let best = 0;
                for (const [name, weight] of Object.entries(FIELD_WEIGHTS)) {
                    const score = matchScore(fields[name], token, name === "key") * weight;
                    if (score > best) best = score;
                }
                if (!best) {
                    total = 0;
                    break;
                }
                total += best;
            }
            if (total) out.push(result(project, s, total));
        }
    }
    if (!tokens.length) out.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)) || a.key.localeCompare(b.key));
    else out.sort((a, b) => b.score - a.score || a.key.length - b.key.length || a.key.localeCompare(b.key) || a.project.localeCompare(b.project));
    return out.slice(0, Math.max(1, Math.min(limit, 200)));
}

module.exports = {
    searchItems: searchItems,
    matchScore: matchScore,
    hostOf: hostOf
};
