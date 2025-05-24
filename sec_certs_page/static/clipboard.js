


async function copyLinkToClipboard (linkObj) {
    try {
        const successSpan = document.createElement('span');

        const iconElement = document.createElement('i');
        iconElement.classList.add('fas', 'fa-check');
        successSpan.appendChild(iconElement);
        successSpan.appendChild(document.createTextNode(' Copied!'));

        await navigator.clipboard.writeText(window.location.host + linkObj.getAttribute("data-url"));
        const originalChildren = linkObj.firstElementChild
        linkObj.replaceChildren(successSpan)
        setTimeout(() => linkObj.replaceChildren(originalChildren), 3000)
    } catch (error) {
        console.error("Failed to copy to clipboard:", error);
    }
};

function copyToClipboard() {
    var text = getSelectionText();
    if (!text || text.length == 0) {
        selectText($(this));
        var success = document.execCommand("copy");
        if (!success)
            console.error("failed to copy text to clipboard :(")
    }
}