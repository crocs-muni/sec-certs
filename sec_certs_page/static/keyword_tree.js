/**
 * keyword_tree.js
 *
 * Renders a collapsible tree of extracted-keyword categories inside a modal and
 * lets the user tick nodes (leaf or internal) to filter the certificate search.
 * Selecting an internal node matches that node or any of its descendants.
 *
 * The module is self-contained and reused across schemes (CC / FIPS / EUCC / PP),
 * differing only in the tree data and which document sources are offered. It does
 * not touch the search-submission flow: it writes its state into hidden
 * `[data-param]` inputs that the existing search.js `searchParams()` collects.
 *
 * Expected markup (see search/base templates):
 *   <script type="application/json" id="keyword-tree-data"> [tree] </script>
 *   <input type="hidden" id="kw-keywords"  data-param="keywords">
 *   <input type="hidden" id="kw-sources"   data-param="kw_sources">   (optional)
 *   <input type="hidden" id="kw-mode"      data-param="kw_mode">
 *   #keyword-tree-container   — tree is rendered here
 *   #keyword-tree-search      — optional text input to filter the tree
 *   #keywords-badge           — optional count badge on the trigger button
 *   .kw-source                — optional document-source checkboxes (value = label)
 *   input[name="kw-mode-radio"] — optional AND/OR radios (value "and"/"or")
 *
 * Each rendered checkbox carries data-path (the dot-joined rules path) for
 * nodes that are selectable; group nodes have no path and only toggle children.
 */

let treeRoot = null; // container element

function buildNode(node) {
    const li = document.createElement("li");
    li.className = "kw-node";

    const row = document.createElement("div");
    row.className = "kw-row";

    const hasChildren = node.children && node.children.length > 0;

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "kw-toggle";
    toggle.setAttribute("aria-label", "Expand");
    toggle.innerHTML = hasChildren ? '<i class="fas fa-caret-right"></i>' : "";
    if (!hasChildren) toggle.classList.add("kw-toggle-empty");
    row.appendChild(toggle);

    const label = document.createElement("label");
    label.className = "kw-label";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "form-check-input kw-check";
    if (node.path) cb.dataset.path = node.path;
    label.appendChild(cb);

    const text = document.createElement("span");
    text.className = "kw-name";
    text.textContent = node.name;
    label.appendChild(text);

    row.appendChild(label);
    li.appendChild(row);

    if (hasChildren) {
        const ul = document.createElement("ul");
        ul.className = "kw-children collapse";
        node.children.forEach(child => ul.appendChild(buildNode(child)));
        li.appendChild(ul);

        toggle.addEventListener("click", () => {
            const open = ul.classList.toggle("show");
            toggle.classList.toggle("kw-open", open);
            toggle.setAttribute("aria-label", open ? "Collapse" : "Expand");
        });
    }

    return li;
}

// --- selection cascade -------------------------------------------------------

function descendantChecks(li) {
    return Array.from(li.querySelectorAll(":scope > .kw-children .kw-check"));
}

function cascadeDown(li, checked) {
    descendantChecks(li).forEach(cb => {
        cb.checked = checked;
        cb.indeterminate = false;
    });
}

function refreshAncestors() {
    // Walk from deepest to shallowest, setting each parent's checked/indeterminate
    // from its direct children.
    const nodes = Array.from(treeRoot.querySelectorAll(".kw-node")).reverse();
    nodes.forEach(li => {
        const childUl = li.querySelector(":scope > .kw-children");
        if (!childUl) return;
        const childChecks = Array.from(childUl.children)
            .map(c => c.querySelector(":scope > .kw-row .kw-check"))
            .filter(Boolean);
        if (!childChecks.length) return;
        const all = childChecks.every(c => c.checked && !c.indeterminate);
        const some = childChecks.some(c => c.checked || c.indeterminate);
        const cb = li.querySelector(":scope > .kw-row .kw-check");
        cb.checked = all;
        cb.indeterminate = !all && some;
    });
}

/**
 * Topmost selected nodes that carry a path. A node is dropped only when an
 * ancestor that *itself* carries a path is fully checked (and therefore already
 * covers it). Group headers have no path, so a fully-checked group still yields
 * its category paths rather than collapsing to nothing.
 */
function selectedPaths() {
    const paths = [];
    treeRoot.querySelectorAll(".kw-check").forEach(cb => {
        if (!cb.checked || cb.indeterminate || !cb.dataset.path) return;
        let li = cb.closest(".kw-node").parentElement;
        let covered = false;
        while (li && li !== treeRoot) {
            if (li.classList.contains("kw-node")) {
                const acb = li.querySelector(":scope > .kw-row .kw-check");
                if (acb && acb.dataset.path && acb.checked && !acb.indeterminate) {
                    covered = true;
                    break;
                }
            }
            li = li.parentElement;
        }
        if (!covered) paths.push(cb.dataset.path);
    });
    return paths;
}

// --- state sync --------------------------------------------------------------

function currentMode() {
    const radio = document.querySelector('input[name="kw-mode-radio"]:checked');
    return radio ? radio.value : "or";
}

function syncState() {
    const paths = selectedPaths();
    document.getElementById("kw-keywords").value = paths.join(",");

    const sourcesInput = document.getElementById("kw-sources");
    if (sourcesInput) {
        const boxes = Array.from(document.querySelectorAll(".kw-source"));
        const checked = boxes.filter(b => b.checked);
        // Empty (= all sources) keeps the URL clean; the server defaults to all.
        sourcesInput.value = checked.length === boxes.length ? "" : checked.map(b => b.value).join(",");
    }

    const mode = currentMode();
    document.getElementById("kw-mode").value = mode === "and" ? "and" : "";

    // Show an "active" indicator rather than a (misleading) selection count.
    const badge = document.getElementById("keywords-badge");
    if (badge) badge.classList.toggle("d-none", paths.length === 0);
}

// --- tree filtering ----------------------------------------------------------

function filterTree(term) {
    term = term.trim().toLowerCase();
    treeRoot.querySelectorAll(".kw-node").forEach(li => {
        const name = li.querySelector(":scope > .kw-row .kw-name").textContent.toLowerCase();
        const selfMatch = !term || name.includes(term);
        li.dataset.selfMatch = selfMatch ? "1" : "";
    });
    // A node is visible if it or any descendant matches; expand the path to matches.
    const nodes = Array.from(treeRoot.querySelectorAll(".kw-node")).reverse();
    nodes.forEach(li => {
        const childUl = li.querySelector(":scope > .kw-children");
        const childVisible = childUl
            ? Array.from(childUl.children).some(c => c.style.display !== "none")
            : false;
        const visible = li.dataset.selfMatch === "1" || childVisible;
        li.style.display = visible ? "" : "none";
        if (childUl && term && childVisible) {
            childUl.classList.add("show");
            const toggle = li.querySelector(":scope > .kw-row .kw-toggle");
            toggle?.classList.add("kw-open");
        }
    });
}

// --- restore from server-rendered hidden inputs ------------------------------

function restore() {
    const raw = document.getElementById("kw-keywords").value;
    if (raw) {
        const wanted = new Set(raw.split(",").filter(Boolean));
        treeRoot.querySelectorAll(".kw-check").forEach(cb => {
            if (cb.dataset.path && wanted.has(cb.dataset.path)) {
                cb.checked = true;
                const li = cb.closest(".kw-node");
                cascadeDown(li, true);
                // expand ancestors so the selection is visible
                let parent = li.parentElement;
                while (parent && parent !== treeRoot) {
                    if (parent.classList.contains("kw-children")) {
                        parent.classList.add("show");
                        const t = parent.closest(".kw-node")?.querySelector(":scope > .kw-row .kw-toggle");
                        t?.classList.add("kw-open");
                    }
                    parent = parent.parentElement;
                }
            }
        });
        refreshAncestors();
    }

    const sourcesInput = document.getElementById("kw-sources");
    if (sourcesInput && sourcesInput.value) {
        const wanted = new Set(sourcesInput.value.split(",").filter(Boolean));
        document.querySelectorAll(".kw-source").forEach(b => { b.checked = wanted.has(b.value); });
    }

    const mode = document.getElementById("kw-mode").value || "or";
    const radio = document.querySelector(`input[name="kw-mode-radio"][value="${mode}"]`);
    if (radio) radio.checked = true;

    syncState();
}

export function resetKeywordTree() {
    if (!treeRoot) return;
    treeRoot.querySelectorAll(".kw-check").forEach(cb => { cb.checked = false; cb.indeterminate = false; });
    document.querySelectorAll(".kw-source").forEach(b => { b.checked = true; });
    const orRadio = document.querySelector('input[name="kw-mode-radio"][value="or"]');
    if (orRadio) orRadio.checked = true;
    syncState();
}

export function initKeywordTree() {
    const dataEl = document.getElementById("keyword-tree-data");
    treeRoot = document.getElementById("keyword-tree-container");
    if (!dataEl || !treeRoot) return;

    const tree = JSON.parse(dataEl.textContent);
    const ul = document.createElement("ul");
    ul.className = "kw-tree";
    tree.forEach(node => ul.appendChild(buildNode(node)));
    treeRoot.innerHTML = "";
    treeRoot.appendChild(ul);

    treeRoot.addEventListener("change", e => {
        const cb = e.target.closest(".kw-check");
        if (!cb) return;
        cb.indeterminate = false;
        cascadeDown(cb.closest(".kw-node"), cb.checked);
        refreshAncestors();
        syncState();
    });

    document.querySelectorAll(".kw-source").forEach(b => b.addEventListener("change", syncState));
    document.querySelectorAll('input[name="kw-mode-radio"]').forEach(r => r.addEventListener("change", syncState));

    const search = document.getElementById("keyword-tree-search");
    if (search) search.addEventListener("input", () => filterTree(search.value));

    // Keep the tree consistent when the shared "Reset" button clears hidden inputs.
    document.getElementById("reset-filters-btn")?.addEventListener("click", resetKeywordTree);
    document.getElementById("keyword-tree-clear")?.addEventListener("click", resetKeywordTree);

    restore();
}
