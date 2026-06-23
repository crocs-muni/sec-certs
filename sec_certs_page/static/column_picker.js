/**
 * column_picker.js
 *
 * Toggle visibility of result-table columns, persisted in localStorage.
 *
 * cols: [{ key, label, defaultVisible?, locked? }]
 *   key            matches the data-col attribute on the <col>/<th>/<td> elements.
 *   locked         column is always visible and disabled in the picker.
 *                  (Legacy: a column keyed "name" is locked by default.)
 *
 * Hiding is done with a single injected stylesheet rule per hidden column
 * (`#results [data-col="key"] { display: none }`) rather than toggling a class on
 * every cell. That makes a toggle O(columns) instead of O(rows × columns), and the
 * rule keeps applying to rows inserted later (e.g. after an AJAX results swap) with
 * no re-apply needed.
 */

const STYLE_ID = "col-visibility-style";

function isLocked(col) {
    return col.locked === true || col.key === "name";
}

function loadVisible(cols, storageKey) {
    let saved = null;
    try {
        saved = JSON.parse(localStorage.getItem(storageKey));
    } catch {}

    const savedFor = key => (saved && typeof saved === "object" ? saved[key] : undefined);
    const visible = Object.fromEntries(
        cols.map(c => [c.key, savedFor(c.key) ?? (c.defaultVisible ?? true)])
    );
    cols.forEach(c => { if (isLocked(c)) visible[c.key] = true; });
    return visible;
}

function saveVisible(storageKey, visible) {
    localStorage.setItem(storageKey, JSON.stringify(visible));
}

function styleEl() {
    let el = document.getElementById(STYLE_ID);
    if (!el) {
        el = document.createElement("style");
        el.id = STYLE_ID;
        document.head.appendChild(el);
    }
    return el;
}

export function applyColumnVisibility(cols, visible, onAfterApply) {
    const hidden = cols.filter(c => !visible[c.key]).map(c => c.key);

    styleEl().textContent = hidden
        .map(key => `#results [data-col="${CSS.escape(key)}"] { display: none; }`)
        .join("\n");

    // A hidden column must not stay the active sort column.
    hidden.forEach(key => {
        document.querySelector(`th[data-col="${CSS.escape(key)}"]`)?.classList.remove("sort-asc", "sort-desc");
    });

    onAfterApply?.();
}

function renderPicker(cols, visible, storageKey, onAfterApply) {
    const list = document.getElementById("col-list");
    if (!list) return;

    list.innerHTML = cols.map(col => `
        <li>
            <label class="dropdown-item d-flex align-items-center gap-2">
                <input type="checkbox"
                       ${visible[col.key] ? "checked" : ""}
                       ${isLocked(col) ? "disabled" : ""}
                       data-col-toggle="${col.key}">
                ${col.label}
            </label>
        </li>
    `).join("");

    list.querySelectorAll("[data-col-toggle]").forEach(cb => {
        cb.addEventListener("change", () => {
            visible[cb.dataset.colToggle] = cb.checked;
            saveVisible(storageKey, visible);
            applyColumnVisibility(cols, visible, onAfterApply);
        });
    });

    const setAll = (state) => {
        cols.forEach(c => { visible[c.key] = isLocked(c) ? true : state; });
        saveVisible(storageKey, visible);
        applyColumnVisibility(cols, visible, onAfterApply);
        renderPicker(cols, visible, storageKey, onAfterApply);
    };

    document.getElementById("col-show-all")?.addEventListener("click", () => setAll(true));
    document.getElementById("col-hide-all")?.addEventListener("click", () => setAll(false));
}

export function initColumnPicker({ cols, storageKey, onAfterApply } = {}) {
    const visible = loadVisible(cols, storageKey);
    const rerender = () => renderPicker(cols, visible, storageKey, onAfterApply);
    rerender();
    applyColumnVisibility(cols, visible, onAfterApply);
    return { visible, rerender };
}
