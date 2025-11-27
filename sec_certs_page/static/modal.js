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

export function chat(rag_url, full_url, token, chat_history, certificate_data) {
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
            case "rag-this":
                url = rag_url;
                data.about = "entry";
                break;
            case "rag-both":
                url = rag_url;
                data.about = "both";
                break;
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
        $("#chat-messages").append(`<div class="chat-message-user">${message}</div>`);
        $("#chat-input").val(""); // Clear input after sending
        // Disable the send button to prevent multiple clicks
        $("#chat-send").prop("disabled", true);
        // Show the loading indicator
        $("#chat-messages").append(`<div class="chat-message-loading"><i class="fas fa-spinner fa-spin"></i></div>`);
        // Send the chat history to the server
        $.ajax(url, {
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
            if (data.files && data.files.length > 0) {
                $("#chat-files").html(
                    `Files available for RAG <span class="badge bg-secondary">${data.files.join(", ")}</span>`
                );
            } else {
                $("#chat-files").text("No files available for RAG. This wil not work!");
            }
            $("#chat-files").data("done", true);
        },
        error: function (xhr) {
            let error_message = "An error occurred while fetching files.";
            if (xhr.responseJSON && xhr.responseJSON.message) {
                error_message = xhr.responseJSON.message;
            }
            $("#chat-files").text(error_message).addClass("text-danger");
        }
    })
}