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

export function chat(full_url, token, chat_history, certificate_data) {
    let message = $("#chat-input").val().trim();
    if (message) {
        // Append the message to the chat history and display it
        let full_message = {
            role: "user",
            content: message
        };
        chat_history.push(full_message);
        let data = {
            query: chat_history,
        };
        let about = $("#chat-about").val();
        let url;
        switch (about) {
            case "full-report":
                url = full_url;
                data.context = "report";
                break;
            case "full-target":
                url = full_url;
                data.context = "target";
                break;
            case "full-both":
                url = full_url;
                data.context = "both";
                break;
            default:
                // Error out
                return;
        }
        // Get the model
        data.model = $("#chat-model").val();
        // Extract hashid from certificate_data if available
        let hashid = certificate_data?.hashid;
        let collection = certificate_data?.type;
        if (hashid !== undefined) {
            data.hashid = hashid;
            data.collection = collection;
        }
        // Hide the empty state and render the user's turn
        $("#chat-empty").addClass("d-none");
        let userTurn = $('<div class="chat-turn user"><div class="chat-bubble"></div></div>');
        userTurn.find(".chat-bubble").text(message);
        $("#chat-messages").append(userTurn);
        $("#chat-input").val("").trigger("input"); // Clear input (also resets autogrow + send state)
        $("#chat-send").prop("disabled", true);
        // Show the typing indicator
        let loading = $(
            '<div class="chat-turn assistant chat-loading">' +
            '<span class="chat-avatar"><i class="fas fa-wand-magic-sparkles"></i></span>' +
            '<div class="chat-turn-body"><span class="chat-dots"><i></i><i></i><i></i></span></div></div>'
        );
        $("#chat-messages").append(loading);
        scrollChatToBottom();
        // Send the chat history to the server
        $.ajax(url, {
                method: "POST",
                contentType: "application/json",
                data: JSON.stringify(data),
                headers: {
                    "X-CSRFToken": token
                },
                success: function (response) {
                    $("#chat-messages .chat-loading").remove();
                    let botTurn = $(
                        '<div class="chat-turn assistant">' +
                        '<span class="chat-avatar"><i class="fas fa-wand-magic-sparkles"></i></span>' +
                        '<div class="chat-turn-body"><div class="chat-md"></div></div></div>'
                    );
                    botTurn.find(".chat-md").html(response.response);
                    $("#chat-messages").append(botTurn);
                    chat_history.push({
                        role: "assistant",
                        content: response.raw
                    });
                    $("#chat-error").hide();
                    // Re-enable send based on the current input state
                    $("#chat-send").prop("disabled", $("#chat-input").val().trim() === "");
                    scrollChatToBottom();
                },
                error: function (xhr) {
                    $("#chat-messages .chat-loading").remove();
                    let error_message = "An error occurred while sending your message.";
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        error_message = xhr.responseJSON.message;
                    }
                    let noticeTurn = $(
                        '<div class="chat-turn assistant chat-notice-turn">' +
                        '<span class="chat-avatar"><i class="fas fa-triangle-exclamation"></i></span>' +
                        '<div class="chat-turn-body"><div class="chat-md"></div></div></div>'
                    );
                    noticeTurn.find(".chat-md").text(error_message);
                    $("#chat-messages").append(noticeTurn);
                    $("#chat-error").hide();
                    $("#chat-send").prop("disabled", $("#chat-input").val().trim() === "");
                    scrollChatToBottom();
                }
            }
        );
    }
}
