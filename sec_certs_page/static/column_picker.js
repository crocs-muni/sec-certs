function loadVisible(cols, storageKey) {
    try {
        const saved = JSON.parse(localStorage.getItem(storageKey));
        if (saved) {
            saved.name = true; // name is always visible
            return saved;
        }
    } catch {}
    return Object.fromEntries(cols.map(c => [c.key, c.defaultVisible ?? true]));
}

function saveVisible(storageKey, visible) {
    localStorage.setItem(storageKey, JSON.stringify(visible));
}

export function applyColumnVisibility(cols, visible, onAfterApply) {
    cols.forEach(({ key }) => {
        const hidden = !visible[key];
        document.querySelectorAll(`[data-col="${key}"]`).forEach(el => {
            el.classList.toggle('col-hidden', hidden);
        });
        if (hidden) {
            document.querySelector(`th[data-col="${key}"]`)
                ?.classList.remove('sort-asc', 'sort-desc');
        }
    });
    onAfterApply?.();
}

function renderPicker(cols, visible, storageKey, onAfterApply) {
    const list = document.getElementById('col-list');
    if (!list) return;

    list.innerHTML = cols.map(({ key, label }) => `
        <li>
            <label class="dropdown-item d-flex align-items-center gap-2">
                <input type="checkbox"
                       ${visible[key] ? 'checked' : ''}
                       ${key === 'name' ? 'disabled' : ''}
                       data-col-toggle="${key}">
                ${label}
            </label>
        </li>
    `).join('');

    list.querySelectorAll('[data-col-toggle]').forEach(cb => {
        cb.addEventListener('change', () => {
            visible[cb.dataset.colToggle] = cb.checked;
            saveVisible(storageKey, visible);
            applyColumnVisibility(cols, visible, onAfterApply);
        });
    });

    const setAll = (state) => {
        cols.forEach(c => { visible[c.key] = c.key === 'name' ? true : state; });
        saveVisible(storageKey, visible);
        applyColumnVisibility(cols, visible, onAfterApply);
        renderPicker(cols, visible, storageKey, onAfterApply);
    };

    document.getElementById('col-show-all')?.addEventListener('click', () => setAll(true));
    document.getElementById('col-hide-all')?.addEventListener('click', () => setAll(false));
}

export function initColumnPicker({ cols, storageKey, onAfterApply } = {}) {
    const visible = loadVisible(cols, storageKey);
    const rerender = () => renderPicker(cols, visible, storageKey, onAfterApply);
    rerender();
    applyColumnVisibility(cols, visible, onAfterApply);
    return { visible, rerender };
}