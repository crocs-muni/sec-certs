/**
 * search_results.js
 *
 * Reusable wiring for a search results table. Consolidates what each search page
 * previously duplicated inline: column picker, sortable headers, AJAX results
 * fetching + swap, validation-error rendering, and pagination/ajax-search handlers.
 *
 *   initSearchResults({
 *     endpoint,                 // search route URL (also receives ?<searchParams()>)
 *     cols, storageKey,         // optional: enables the column picker
 *     fieldMap,                 // { errorKey: "#inputSelector" } for inline errors
 *     onAfterApply,             // optional: run after rows render/swap (e.g. tooltips)
 *     sortBy, sortDir,          // initial sort state (from the server)
 *   });
 *
 * Column visibility is applied via a persistent stylesheet rule (see column_picker.js),
 * so it survives AJAX row swaps without being re-applied per fetch.
 */

import { resultsFetch, searchParams, hasActiveCriteria } from "./search.js";
import { initColumnPicker } from "./column_picker.js";
import { initSortable, setSort } from "./sortable.js";

function initClampTooltips() {
    document.querySelectorAll('.result-clamp').forEach(el => {
        bootstrap.Tooltip.getInstance(el)?.dispose();
        el.removeAttribute('title');
        if (el.offsetWidth === 0) return;
        if (el.scrollHeight > el.clientHeight) {
            el.title = el.textContent.trim();
            new bootstrap.Tooltip(el, { placement: 'top' });
        }
    });
}

export function initSearchResults({
    endpoint,
    cols = null,
    storageKey = null,
    fieldMap = {},
    onAfterApply = null,
    sortBy = "",
    sortDir = "",
} = {}) {
    function applyErrors(errors) {
        $("[data-feedback]").removeClass("is-invalid");
        $(".invalid-feedback").empty();
        for (const [key, messages] of Object.entries(errors)) {
            const selector = fieldMap[key];
            if (!selector) continue;
            const $input = $(selector);
            $(`#${$input.data("feedback")}`).html(messages.map(m => `<div>${m}</div>`).join(""));
            $input.addClass("is-invalid");
        }
    }

    const afterApply = () => { initClampTooltips(); onAfterApply?.(); };

    const picker = cols && storageKey ? initColumnPicker({ cols, storageKey, onAfterApply: afterApply }) : null;

    const doFetch = resultsFetch(function onSwap() {
        const c = document.getElementById("results");
        applyErrors(JSON.parse(c.dataset.errors || "{}"));
        setSort(c.dataset.sortBy, c.dataset.sortDir);
        afterApply();
    });

    initSortable(() => doFetch(`${endpoint}?${searchParams()}`), hasActiveCriteria);
    picker?.rerender();
    setSort(sortBy, sortDir);

    document.addEventListener("ajax-search", e => {
        e.preventDefault();
        doFetch(e.detail.url);
    });

    document.addEventListener("click", e => {
        const a = e.target.closest("a[href]");
        if (!a) return;
        const container = document.getElementById("results");
        if (!container?.contains(a) || !a.closest(".pagination")) return;
        e.preventDefault();
        doFetch(a.href);
    });

    return { doFetch, picker };
}
