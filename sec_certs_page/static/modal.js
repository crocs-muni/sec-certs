// Detect available storage: prefer localStorage, fall back to sessionStorage, else null.
const storage = (() => {
    const test = '__storage_test__';
    const candidates = [
        () => window.localStorage,
        () => window.sessionStorage
    ];
    for (const getStorage of candidates) {
        try {
            const s = getStorage();
            if (s) {
                s.setItem(test, test);
                s.removeItem(test);
                return s;
            }
        } catch (e) {
            // storage unavailable or access denied, try next
        }
    }
    return null;
})();

function update_state_core(type, storage_key, action, enable, enable_callback, show) {
    if (typeof certificate_data !== "undefined") {
        $(`#${type}-add-current`).show();
    }

    let selected = storage ? storage.getItem(storage_key) : null;
    if (selected === null) {
        if (enable(0)) {
            enable_callback(selected);
            $(`#${type}-${action}`).show();
        } else {
            $(`#${type}-${action}`).hide();
        }
        $(`#${type}-pill`).text("0");
        $(`#${type}-some tbody tr`).remove();
    } else {
        selected = JSON.parse(selected);
        $(`#${type}-pill`).text(selected.length);
        $(`#${type}-some tbody tr`).remove();
        if (show(selected.length)) {
            $(`#${type}-none`).hide();
            $(`#${type}-some`).show();
            if (typeof certificate_data !== "undefined") {
                if (selected.map(cert => cert["hashid"]).includes(certificate_data.hashid)) {
                    $(`#${type}-add-current`).hide();
                }
            }
            for (let [i, cert] of selected.entries()) {
                let tr = $("<tr>").data("cert-hashid", cert["hashid"]).data("cert-type", cert["type"]);
                let num = $("<td>").append(`${i + 1}.`);
                let cat = $("<td>").append(cert["type"].toUpperCase());
                let name = $("<td>").append($("<a>").attr("href", cert["url"]).text(cert["name"]));
                let but = $("<td>").append($("<button>").addClass("btn btn-danger mx-1").prop("type", "button").text("Remove").click(_.curry(remove_cert)(storage_key)));
                tr.append(num).append(cat).append(name).append(but).appendTo($(`#${type}-some tbody`));
            }
        } else {
            $(`#${type}-none`).show();
            $(`#${type}-some`).hide();
        }
        if (enable(selected.length)) {
            enable_callback(selected);
            $(`#${type}-${action}`).show();
        } else {
            $(`#${type}-${action}`).hide();
        }
    }
}

export function update_state() {
    update_state_core("compare",
        "selected_certs_comparison",
        "do",
        (len) => len === 2,
        () => {
        },
        (len) => len > 0);
}

export function remove_cert(storage_key, event) {
    if (!storage) return;
    let elem = $(event.target).parents("tr");
    let selected = storage.getItem(storage_key);
    selected = JSON.parse(selected).filter(cert => cert["hashid"] !== elem.data("cert-hashid"));
    if (selected.length === 0) {
        storage.removeItem(storage_key);
    } else {
        storage.setItem(storage_key, JSON.stringify(selected));
    }
    update_state();
}

export function add_current_cert(storage_key, current) {
    if (!storage) return;
    let selected = storage.getItem(storage_key);
    if (selected === null) {
        selected = [current];
    } else {
        selected = JSON.parse(selected);
        if (current["type"] === "cc" || current["type"] === "fips" || current["type"] === "eucc") {
        	selected.push(current);
        } else {
            $("#compare-error").text("Comparing protection profiles not supported (yet).").show();
            return;
        }
    }
    storage.setItem(storage_key, JSON.stringify(selected));
    update_state();
}

export function compare_do(cc_url, fips_url, eucc_url) {
    let selected = storage ? storage.getItem("selected_certs_comparison") : null;
    if (selected === null) {
        //whoops
        $("#compare-error").text("This should not have happened. Please report a bug and clear your browser's localStorage.").show();
        return;
    }
    selected = JSON.parse(selected);
    if (selected.length !== 2) {
        $("#compare-error").text("You can only compare two certificates.").show();
        return;
    }
    if (selected[0]["type"] !== selected[1]["type"]) {
        $("#compare-error").text("You can only compare certificates from the same framework (i.e. CC, EUCC or FIPS).").show();
        return;
    }
    let url;
    if (selected[0]["type"] === "cc") {
        url = cc_url;
    } else if (selected[0]["type"] === "eucc") {
        url = eucc_url;
    } else if (selected[0]["type"] === "fips") {
        url = fips_url;
    } else if (selected[0]["type"] === "pp") {
        $("#compare-error").text("Comparing protection profiles not supported (yet).").show();
        return;
    }
    url = url.replace("XXXXXXXXXXXXXXXX", selected[0]["hashid"]);
    url = url.replace("YYYYYYYYYYYYYYYY", selected[1]["hashid"]);
    window.location.href = url;
}

function scrollChatToBottom() {
    let win = document.getElementById("chat-window");
    if (win) {
        win.scrollTop = win.scrollHeight;
    }
}

function buildChatRequest(chat_history, certificate_data) {
    let context = $("#chat-about").val();
    if (!["report", "target", "both"].includes(context)) return null;
    let data = {query: chat_history, context: context, model: $("#chat-model").val()};
    if (certificate_data?.hashid !== undefined) {
        data.hashid = certificate_data.hashid;
        data.collection = certificate_data.type;
    }
    return data;
}

function assistantTurn(iconClass, bodyHtml, extraClass) {
    return $(
        `<div class="chat-turn assistant${extraClass ? " " + extraClass : ""}">` +
        `<span class="chat-avatar"><i class="fas ${iconClass}"></i></span>` +
        `<div class="chat-turn-body">${bodyHtml}</div></div>`
    );
}

function appendUserTurn(message) {
    let turn = $('<div class="chat-turn user"><div class="chat-bubble"></div></div>');
    turn.find(".chat-bubble").text(message);
    $("#chat-messages").append(turn);
}

function appendLoadingTurn() {
    $("#chat-messages").append(assistantTurn("fa-wand-magic-sparkles", '<span class="chat-dots"><i></i><i></i><i></i></span>', "chat-loading"));
}

function appendAssistantTurn() {
    $("#chat-messages .chat-loading").remove();
    let turn = assistantTurn("fa-wand-magic-sparkles", '<div class="chat-md"></div>');
    $("#chat-messages").append(turn);
    return turn.find(".chat-md");
}

function appendErrorTurn(message) {
    $("#chat-messages .chat-loading").remove();
    let turn = assistantTurn("fa-triangle-exclamation", '<div class="chat-md"></div>', "chat-notice-turn");
    turn.find(".chat-md").text(message || "An error occurred while sending your message.");
    $("#chat-messages").append(turn);
    $("#chat-error").hide();
    reenableSend();
    scrollChatToBottom();
}

function reenableSend() {
    $("#chat-send").removeClass("chat-pending").prop("disabled", $("#chat-input").val().trim() === "");
}

function renderMarkdown($md, text) {
    $md.html(DOMPurify.sanitize(marked.parse(text)));
    $md.find("a").attr({target: "_blank", rel: "noopener noreferrer"});
}

async function* readSSEFrames(response) {
    let reader = response.body.getReader();
    let decoder = new TextDecoder();
    let buffer = "";
    while (true) {
        let {value, done} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream: true});
        let idx;
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
            yield parseSSEFrame(buffer.slice(0, idx));
            buffer = buffer.slice(idx + 2);
        }
    }
}

function parseSSEFrame(frame) {
    let event = "message";
    let dataStr = "";
    for (let line of frame.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataStr += line.slice(5).trim();
    }
    let data = {};
    try {
        if (dataStr) data = JSON.parse(dataStr);
    } catch (e) {
        // leave data as {}
    }
    return {event, data};
}

async function errorMessage(response) {
    try {
        return (await response.json())?.message;
    } catch (e) {
        return undefined;
    }
}

async function streamReply(url, token, data, chat_history) {
    let response;
    try {
        response = await fetch(url, {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRFToken": token},
            body: JSON.stringify(data)
        });
    } catch (e) {
        appendErrorTurn();
        return;
    }
    if (!response.ok) {
        appendErrorTurn(await errorMessage(response));
        return;
    }

    let botMd = appendAssistantTurn();
    let raw = "";
    try {
        for await (let {event, data: payload} of readSSEFrames(response)) {
            if (event === "error") {
                botMd.closest(".chat-turn").remove();
                appendErrorTurn(payload.message);
                return;
            }
            if (event === "done") break;
            if (payload.delta) {
                raw += payload.delta;
                renderMarkdown(botMd, raw);
                scrollChatToBottom();
            }
        }
    } catch (e) {
        botMd.closest(".chat-turn").remove();
        appendErrorTurn();
        return;
    }

    renderMarkdown(botMd, raw);
    if (raw) chat_history.push({role: "assistant", content: raw});
    $("#chat-error").hide();
    reenableSend();
    scrollChatToBottom();
}

export async function chat(full_url, token, chat_history, certificate_data) {
    let message = $("#chat-input").val().trim();
    if (!message) return;

    let data = buildChatRequest(chat_history, certificate_data);
    if (!data) return;
    chat_history.push({role: "user", content: message});

    $("#chat-empty").addClass("d-none");
    appendUserTurn(message);
    $("#chat-input").val("").trigger("input");
    $("#chat-send").prop("disabled", true).addClass("chat-pending");
    appendLoadingTurn();
    scrollChatToBottom();

    await streamReply(full_url, token, data, chat_history);
}
