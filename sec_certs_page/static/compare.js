export function compare_do(cc_url, fips_url) {
    let selected = localStorage.getItem("selected_certs_comparison");
    if (selected === null) {
        //whoops
        return;
    }
    selected = JSON.parse(selected);
    if (selected.length !== 2) {
        return;
    }
    if (selected[0]["type"] !== selected[1]["type"]) {
        return;
    }
    let url;
    if (selected[0]["type"] === "cc") {
        url = cc_url;
    } else {
        url = fips_url;
    }
    url = url.replace("XXXXXXXXXXXXXXXX", selected[0]["hashid"]);
    url = url.replace("YYYYYYYYYYYYYYYY", selected[1]["hashid"]);
    window.location.href = url;
}