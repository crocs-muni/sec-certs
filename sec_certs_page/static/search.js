import {
    initYearRangeSliders,
    resetYearRangeSliders,
} from "./year_range_slider.js";

export function nameSearchSetup() {
    document.getElementById("nameSearchRadioId").checked = true;
    document.querySelectorAll(".fulltext-only").forEach(el => el.classList.add("d-none"));
    document.querySelectorAll(".name-only").forEach(el => el.classList.remove("d-none"));
    $(`#name`).val("")
}

export function fulltextSearchSetup() {
    document.getElementById("fulltextSearchRadioId").checked = true;
    document.querySelectorAll(".fulltext-only").forEach(el => el.classList.remove("d-none"));
    document.querySelectorAll(".name-only").forEach(el => el.classList.add("d-none"));
}

// Encode a checkbox group (#search-<name>) into a query value, or null when every
// option is checked (= no filter). `data-encoding` picks the wire format:
//   bitmask -> hex OR of (1 << index) over checked boxes (schemes, eal, level)
//   concat  -> data-id values of checked boxes joined (categories)
function collectGroup(group) {
    const inputs = group.querySelectorAll("input");
    const checked = group.querySelectorAll("input:checked");
    if (checked.length === inputs.length) return null;

    if (group.dataset.encoding === "bitmask") {
        let bits = 0;
        inputs.forEach((el, i) => { if (el.checked) bits |= (1 << i); });
        return bits.toString(16);
    }
    return $.makeArray(checked).map(el => el.dataset.id).join("");
}

function getSort() {
    const th = document.querySelector('th.sort-asc, th.sort-desc');
    if (!th) return null;

    const dir = th.classList.contains('sort-asc') ? 'asc' : 'desc';
    // Suppress params only for the default column in its default (desc) direction,
    // so the URL stays clean and a fresh query falls back to relevance ranking.
    // A flipped default column (asc) must be sent explicitly.
    if (th.dataset.defaultSort === "true" && dir === "desc") return null;

    return [th.dataset.col, dir];
}

export function searchParams(additional) {
    const searchType = $("#nameSearchRadioId").is(":checked") ? "name" : "fulltext";
    const [sort_by, sort_dir] = getSort() ?? [];
    const params = { search_type: searchType, sort_by, sort_dir };

    document.querySelectorAll("[data-param]").forEach(el => {
        params[el.dataset.param] = el.value;
    });
    document.querySelectorAll("[data-search-group]").forEach(group => {
        params[group.dataset.param] = collectGroup(group);
    });

    Object.assign(params, additional);

    Object.keys(params).forEach(key => {
        if (params[key] == null || params[key] === "") delete params[key];
    });

    return $.param(params);
}

// Group name is the #search-<name> suffix; its error element is #<name>-error.
function groupName(group) {
    return group.id.replace(/^search-/, "");
}

function checkAtLeastOne(group) {
    const $error = $(`#${groupName(group)}-error`);
    if (group.querySelectorAll("input:checked").length === 0) {
        $error.text("Select at least one.").show();
        return false;
    }
    $error.hide();
    return true;
}

function checkDateRange(fromId, toId, errorId) {
    const fromInput = document.getElementById(fromId);
    const toInput   = document.getElementById(toId);
    const $from = $(`#${fromId}`);
    const $to = $(`#${toId}`);
    const $error = $(`#${errorId}`);

    $from.removeClass("is-invalid");
    $to.removeClass("is-invalid");

    if (fromInput.validity.badInput) {
        $from.addClass("is-invalid");
        $error.text("Invalid date.").show();
        return false;
    }
    if (toInput.validity.badInput) {
        $to.addClass("is-invalid");
        $error.text("Invalid date.").show();
        return false;
    }
    if (fromInput.value && toInput.value && fromInput.value > toInput.value) {
        $from.addClass("is-invalid");
        $to.addClass("is-invalid");
        $error.text("Invalid range.").show();
        return false;
    }

    $error.hide();
    return true;
}

function checkSearch() {
    let ok = true;
    document.querySelectorAll("[data-search-group]").forEach(group => {
        ok = checkAtLeastOne(group) && ok;
    });

    const ranges = new Set();
    document.querySelectorAll("[data-range]").forEach(el => ranges.add(el.dataset.range));
    ranges.forEach(range => {
        const from = document.querySelector(`[data-range="${range}"][data-param$="_from"]`);
        const to = document.querySelector(`[data-range="${range}"][data-param$="_to"]`);
        ok = checkDateRange(from.id, to.id, `${range}-error`) && ok;
    });

    return ok;
}

export function search(endpointUrl) {
    return function () {
        if (!checkSearch()) return;
        const url = `${endpointUrl}?${searchParams()}`;
        const handled = !document.dispatchEvent(
            new CustomEvent('ajax-search', { detail: { url }, cancelable: true })
        );
        if (!handled) location.href = url;
    };
}

export function networkSearch(endpointUrl) {
    return function (event) {
        if (!checkSearch()) return;
        location.href = `${endpointUrl}?` + searchParams({search: "basic"});
    }
}

function updateCountBadge(group) {
    const count = group.querySelectorAll("input:checked").length;
    $(`#${groupName(group)}-badge`).text(count).attr("aria-label", `${count} selected`);
}

function initStatusDropdown() {
    $(document).on("change", ".status-radio", function () {
        const val = $(this).val();
        const label = $(this).closest("label").text().trim();
        $("#search-status").val(val);
        $("#status-label").text(label);
        $("#status-dropdown-btn").attr("aria-label", `Status: ${label}`);
        $(".dropdown-menu[aria-labelledby='status-dropdown-btn'] [role='menuitemradio']")
            .attr("aria-checked", "false");
        $(this).closest("[role='menuitemradio']").attr("aria-checked", "true");
    });
}

function initDropdownKeyboard() {
    $(document).on("keydown", ".dropdown-menu .dropdown-item", function (e) {
        if (e.key !== "Enter" && e.key !== " ") return;
        e.preventDefault();
        const input = $(this).find("input[type='checkbox'], input[type='radio']");
        if (!input.length) return;
        if (input.attr("type") === "checkbox") {
            input.prop("checked", !input.prop("checked")).trigger("change");
        } else {
            input.prop("checked", true).trigger("change");
        }
    });
}

// CC keeps the status field in the search-type-specific column; move it into the
// last visible column of the active mode so it fills the empty grid cell. Opt-in
// via #status-container[data-relocate]; sections without it (FIPS) keep status put.
function relocateStatus(modeSelector) {
    const status = document.getElementById("status-container");
    if (!status || status.dataset.relocate === undefined) return;
    $(status).appendTo(`${modeSelector}:not(.d-none):last`);
}

function resetFilters() {
    // Reset filter fields only; leave the main query box untouched.
    document.querySelectorAll("[data-param]:not([data-param='query'])")
        .forEach(el => $(el).val("").removeClass("is-invalid"));
    $(".invalid-feedback").empty().hide();
    $(".status-radio[value='']").prop("checked", true).trigger("change");
    document.querySelectorAll("[data-search-group]").forEach(group => {
        $(group).find("input").prop("checked", true);
        updateCountBadge(group);
    });
    resetYearRangeSliders();
}

export function initSearch({ searchUrl, networkUrl }) {
    initStatusDropdown();
    initDropdownKeyboard();

    $(document).ready(() => {
        initYearRangeSliders();

        const doSearch = search(searchUrl);
        const doNetworkSearch = networkSearch(networkUrl);

        const initName = () => { nameSearchSetup(); relocateStatus(".name-only"); };
        const initFulltext = () => { fulltextSearchSetup(); relocateStatus(".fulltext-only"); };

        $("#nameSearchRadioId").click(initName);
        $("#fulltextSearchRadioId").click(initFulltext);
        $("#search-btn").click(doSearch);
        $("#network-btn").click(doNetworkSearch);
        $("#search").keyup(e => { if (e.keyCode === 13) doSearch(); });

        document.querySelectorAll("[data-search-group]").forEach(group => {
            $(group).on("change", "input", () => updateCountBadge(group));
            updateCountBadge(group);
        });

        $(document).on("click", "[data-group-action]", function () {
            const group = $(this).closest(".dropdown").find("[data-search-group]")[0];
            if (!group) return;
            $(group).find("input").prop("checked", this.dataset.groupAction === "select");
            updateCountBadge(group);
        });

        $("#reset-filters-btn").click(resetFilters);

        if (document.getElementById("nameSearchRadioId").checked) {
            initName();
        } else {
            initFulltext();
        }
    });
}

export function resultsFetch(onSwap) {
    return async function doFetch(url) {
        const container = document.getElementById('results');
        container.style.opacity = '0.5';
        let res;
        try {
            res = await fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        } finally {
            container.style.opacity = '1';
        }
        if (!res.ok) return;

        const html = await res.text();
        const parsed = new DOMParser().parseFromString(html, 'text/html');
        const partial = parsed.getElementById('search-partial');
        if (!partial) return;

        // Swap only the tbody — colgroup, thead, and column picker stay untouched
        document.getElementById('results-body').replaceWith(
            parsed.getElementById('results-body')
        );

        // Sync pagination top (visibility class + inner content)
        const newTop = partial.querySelector('#pagination-top-wrapper');
        const domTop = document.getElementById('pagination-top-wrapper');
        domTop.className = newTop.className;
        document.getElementById('pagination-info').innerHTML =
            newTop.querySelector('#pagination-info').innerHTML;
        document.getElementById('pagination-links-top').innerHTML =
            newTop.querySelector('#pagination-links-top').innerHTML;

        // Sync pagination bottom
        const newBottom = partial.querySelector('#pagination-bottom-wrapper');
        const domBottom = document.getElementById('pagination-bottom-wrapper');
        domBottom.className = newBottom.className;
        document.getElementById('pagination-links-bottom').innerHTML =
            newBottom.querySelector('#pagination-links-bottom').innerHTML;
        document.getElementById('pagination-info-bottom').innerHTML =
            newBottom.querySelector('#pagination-info-bottom').innerHTML;

        container.dataset.errors = partial.dataset.errors;
        container.dataset.sortBy = partial.dataset.sortBy ?? '';
        container.dataset.sortDir = partial.dataset.sortDir ?? '';

        history.pushState(null, '', url);
        onSwap?.();
    };
}
