export function notification_subscribe(event, url, sitekey, csrf_token) {
    event.preventDefault();
    let selected = localStorage.getItem("selected_certs_subscription");
    if (selected === null) {
        //whoops
        return;
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