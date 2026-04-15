export function nameSearchSetup() {
    searchSetup("name");
}

export function fulltextSearchSetup() {
    searchSetup("fulltext");
}

function searchSetup(mode) {
    const isName = mode === "name";

    // Radios
    $("#nameSearchRadioId").prop("checked", isName);
    $("#fulltextSearchRadioId").prop("checked", !isName);

    // Controls
    $("#search-type").prop("disabled", isName);
    $("#search-sort").prop("disabled", !isName);

    // Info panels
    $("#name-search-info").css("display", isName ? "block" : "none");
    $("#fulltext-search-info").css("display", isName ? "none" : "block");

    // Tooltips (use DOM elements for bootstrap API)
    const sortEl = document.querySelector("#search-sort-tooltip");
    const typeEl = document.querySelector("#search-type-tooltip");
    const tooltipSort = sortEl ? bootstrap.Tooltip.getInstance(sortEl) : null;
    const tooltipType = typeEl ? bootstrap.Tooltip.getInstance(typeEl) : null;

    if (tooltipSort) {
        isName ? tooltipSort.disable() : tooltipSort.enable();
    }
    if (tooltipType) {
        isName ? tooltipType.enable() : tooltipType.disable();
    }
}

export function searchParams(additional) {
    let searchType = $("#nameSearchRadioId").is(":checked") ? "by-name" : "fulltext"
    let status = $("#search-status").val();
    let sort = $("#search-sort").val();
    let scheme = $("#search-scheme").val();
    let source = $("#search-source").val();
    let type = $("#search-type").val();
    let categories = $.makeArray($("#search-categories input").filter(":checked").map((i, elem) => $(elem).data("id"))).join("");
    let params = {
        searchType,
        q: $("#search").val(),
        cat: categories,
        type: type,
        status: status,
        sort: sort,
        scheme: scheme, ...additional
    };
    if (source) {
        params.source = source;
    }
    return $.param(params);
}

function checkSearch() {
    // Check that at least one category is selected.
    const checked = $("#search-categories input:checked").length;
    if (checked === 0) {
        const element = document.querySelector("#extended");
        let extended = bootstrap.Collapse.getOrCreateInstance(element);
        extended.show();
        $("#categories-error").text("Select at least one category.").show();
        return false;
    } else {
        $("#categories-error").hide();
    }
    return true;
}

export function search(endpointUrl) {
    return function (event) {
        if (!checkSearch()) return;
        location.href = `${endpointUrl}?` + searchParams();
    };
}

export function networkSearch(endpointUrl) {
    return function (event) {
        if (!checkSearch()) return;
        location.href = `${endpointUrl}?` + searchParams({search: "basic"});
    }
}