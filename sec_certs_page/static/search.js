export function nameSearchSetup() {
    document.getElementById("nameSearchRadioId").checked = true
    document.getElementById("search-type").disabled = true;
    document.getElementById("search-sort").disabled = false;
    document.getElementById("name-search-info").style.display = "block";
    document.getElementById("fulltext-search-info").style.display = "none";
    const tooltipSort = bootstrap.Tooltip.getInstance('#search-sort-tooltip')
    tooltipSort.disable()
    const tooltipType = bootstrap.Tooltip.getInstance('#search-type-tooltip')
    tooltipType.enable()
}

export function fulltextSearchSetup() {
    document.getElementById("fulltextSearchRadioId").checked = true
    document.getElementById("search-type").disabled = false;
    document.getElementById("search-sort").disabled = true;
    document.getElementById("name-search-info").style.display = "none";
    document.getElementById("fulltext-search-info").style.display = "block";
    const tooltipSort = bootstrap.Tooltip.getInstance('#search-sort-tooltip')
    tooltipSort.enable()
    const tooltipType = bootstrap.Tooltip.getInstance('#search-type-tooltip')
    tooltipType.disable()
}

export function searchParams(additional) {
    let searchType = $("#nameSearchRadioId").is(":checked") ? "by-name" : "fulltext"
    let status = $("#search-status").val();
    let sort = $("#search-sort").val();
    let scheme = $("#search-scheme").val();
    let type = $("#search-type").val();
    let categories = $.makeArray($("#search-categories input").filter(":checked").map((i, elem) => $(elem).data("id"))).join("");
    return $.param({
        searchType,
        q: $("#search").val(),
        cat: categories,
        type: type,
        status: status,
        sort: sort,
        scheme: scheme, ...additional
    });
}