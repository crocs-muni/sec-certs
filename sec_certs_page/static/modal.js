function update_state_core(type, storage_key, action, enable, enable_callback, show) {
    if (typeof certificate_data !== "undefined") {
        $(`#${type}-add-current`).show();
    }

    let selected = localStorage.getItem(storage_key);
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
    update_state_core("notification",
        "selected_certs_subscription",
        "subscribe",
        (len) => true,
        (selected) => {
            if (selected !== null && selected.length > 0) {
                $("#notifications-updates-all").prop("disabled", false).prop("checked", true);
                $("#notifications-updates-vuln").prop("disabled", false);
                $("#notifications-updates-new").prop("disabled", true);
            } else {
                $("#notifications-updates-all").prop("disabled", true);
                $("#notifications-updates-vuln").prop("disabled", true);
                $("#notifications-updates-new").prop("disabled", false).prop("checked", true);
            }
        },

        (len) => true);
    update_state_core("compare",
        "selected_certs_comparison",
        "do",
        (len) => len === 2,
        () => {
        },
        (len) => len > 0);
}

export function remove_cert(storage_key, event) {
    let elem = $(event.target).parents("tr");
    let selected = localStorage.getItem(storage_key);
    selected = JSON.parse(selected).filter(cert => cert["hashid"] !== elem.data("cert-hashid"));
    if (selected.length === 0) {
        localStorage.removeItem(storage_key);
    } else {
        localStorage.setItem(storage_key, JSON.stringify(selected));
    }
    update_state();
}

export function add_current_cert(storage_key, current) {
    let selected = localStorage.getItem(storage_key);
    if (selected === null) {
        selected = [current];
    } else {
        selected = JSON.parse(selected);
        selected.push(current);
    }
    localStorage.setItem(storage_key, JSON.stringify(selected));
    update_state();
}

export function notification_subscribe(event, url, sitekey, csrf_token) {
    event.preventDefault();
    let selected = localStorage.getItem("selected_certs_subscription");
    if (selected === null) {
        if (!$("#notifications-updates-new").prop("checked")) {
            $("#notifications-error").text("This should not have happened. Please report a bug and clear your browser's localStorage.").show();
            return;
        }
    } else {
        selected = JSON.parse(selected);
    }
    let form = $("#notifications-form").get(0)
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }
    turnstile.render("#notification-turnstile", {
        "sitekey": sitekey,
        "response-field": false,
        "callback": (token) => {
            let updates;
            if ($("#notifications-updates-all").prop("checked")) {
                updates = "all";
            }
            if ($("#notifications-updates-vuln").prop("checked")) {
                updates = "vuln";
            }
            if ($("#notifications-updates-new").prop("checked")) {
                updates = "new";
            }
            $.ajax(url, {
                type: "POST",
                contentType: "application/json",
                data: JSON.stringify({
                    "selected": selected,
                    "email": $("#notifications-email").val(),
                    "updates": updates,
                    "captcha": token
                }),
                headers: {
                    "X-CSRFToken": csrf_token
                },
                success: function () {
                    localStorage.removeItem("selected_certs_subscription");
                    $("#notification-some").hide();
                    $("#notification-done").show();
                    $("#notification-subscribe").hide();
                    $("#notifications-error").hide();
                },
                error: function (response) {
                    try {
                        $("#notifications-error").text(response.responseJSON.error).show();
                    } catch (error) {
                        $("#notifications-error").text("Something went wrong with the subscription request, please try again later").show();
                    }
                }
            })
        }
    });
}

export function compare_do(cc_url, fips_url) {
    let selected = localStorage.getItem("selected_certs_comparison");
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
        $("#compare-error").text("You can only compare certificates from the same framework (i.e. CC or FIPS).").show();
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

export function chat_authorize(check_url, auth_url, sitekey, csrf_token) {
    let auth = false;
    $.ajax(check_url, {
        method: "GET",
        success: function (response) {
            // Check response json for "authorized"
            if (response.authorized) {
                $("#chat-authorize").hide();
                $("#chat-turnstile").hide();
                auth = true;
            } else {
                auth = false;
            }
        },
    }).done(function () {
        if (auth) {
            return; // Already authorized, no need to render turnstile
        }

        turnstile.render("#chat-turnstile", {
            "sitekey": sitekey,
            "response-field": false,
            "callback": (token) => {
                $.ajax(auth_url, {
                    type: "POST",
                    contentType: "application/json",
                    data: JSON.stringify({
                        "captcha": token
                    }),
                    headers: {
                        "X-CSRFToken": csrf_token
                    },
                    success: function () {
                        $("#chat-authorize").hide();
                        $("#chat-turnstile").hide();
                    },
                    error: function (response) {
                        try {
                            $("#chat-error").text(response.responseJSON.error).show();
                        } catch (error) {
                            $("#chat-error").text("Something went wrong with the chat authorization request, please try again later").show();
                        }
                    }
                })
            }
        });
    })
}

export function chat(chat_url, token, chat_history, certificate_data) {
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
            about: $("#chat-about").val()
        };
        // Extract hashid from certificate_data if available
        let hashid = certificate_data?.hashid;
        let collection = certificate_data?.type;
        if (hashid !== undefined) {
            data.hashid = hashid;
            data.collection = collection;
        }
        $("#chat-messages").append(`<div class="chat-message-user">${message}</div>`);
        $("#chat-input").val(""); // Clear input after sending
        // Disable the send button to prevent multiple clicks
        $("#chat-send").prop("disabled", true);
        // Show the loading indicator
        $("#chat-messages").append(`<div class="chat-message-loading"><i class="fas fa-spinner fa-spin"></i></div>`);
        // Send the chat history to the server
        $.ajax(chat_url, {
                method: "POST",
                contentType: "application/json",
                data: JSON.stringify(data),
                headers: {
                    "X-CSRFToken": token
                },
                success: function (response) {
                    // Remove the loading indicator
                    $("#chat-messages .chat-message-loading").remove();
                    // Enable the send button again
                    $("#chat-send").prop("disabled", false);
                    // Append the response from the server
                    $("#chat-messages").append(`<div class="chat-message-assistant">${response.response}</div>`);
                    chat_history.push({
                        role: "assistant",
                        content: response.raw
                    });
                    // Hide any previous error messages
                    $("#chat-error").hide();
                },
                error: function (xhr) {
                    // Remove the loading indicator
                    $("#chat-messages .chat-message-loading").remove();
                    // Enable the send button again
                    $("#chat-send").prop("disabled", false);
                    // Handle error, parse the response as JSON
                    let error_message = "An error occurred while sending your message.";
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        error_message = xhr.responseJSON.message;
                    }
                    // Display the error message
                    $("#chat-error").text(error_message).show();
                }
            }
        );
    }
}

export function chat_files(files_url, token, certificate_data) {
    let hashid = certificate_data?.hashid;
    let collection = certificate_data?.type;
    if ($("#chat-files").data("done") || !hashid || !collection) {
        // If files have already been loaded or no hashid/collection, do nothing
        return;
    }
    $.ajax({
        url: files_url,
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            collection: collection,
            hashid: hashid
        }),
        headers: {
            "X-CSRFToken": token
        },
        success: function (data) {
            if (data.files) {
                $("#chat-files").html(
                    `Files available <span class="badge bg-secondary">${data.files.join(", ")}</span>`
                );
            }
            $("#chat-files").data("done", true);
        },
    })
}