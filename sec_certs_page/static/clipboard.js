/**
 * Returns a jQuery object for the given element, jQuery object, or Event.
 * If an Event is passed, uses its currentTarget.
 * @param {jQuery|jQuery.Event|HTMLElement|Event} elem - The element, jQuery object, or Event.
 * @returns {jQuery} - The jQuery object.
 */
function getJqElement(elem) {
    if (elem instanceof Event && elem.currentTarget) {
        elem = elem.currentTarget;
    }
    if (elem instanceof jQuery.Event) {
        elem = elem.currentTarget || elem.target;
    }
    // Always return a jQuery object
    return !(elem instanceof jQuery) ? $(elem) : elem;
}

/**
 * Copies the provided text to the clipboard using the Clipboard API or a fallback.
 * @param {string} text - The text to copy.
 * @returns {Promise<void>}
 */
export async function copyTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
    } else {
        // Fallback for older browsers
        const $tempInput = $("<input>").val(text).appendTo("body");
        $tempInput[0].select();
        document.execCommand('copy');
        $tempInput.remove();
    }
}

/**
 * Copies the URL from a link element's data-url attribute to the clipboard and shows a success message.
 * @param {jQuery|HTMLElement|Event} input - The link element or jQuery object.
 * @returns {Promise<void>}
 */
export async function copyLinkToClipboard(input) {
    const $el = getJqElement(input || this).eq(0);
    const textToCopy = $el.attr("data-url");
    const $successSpan = $("<span>").append($("<i>").addClass("fas fa-check")).append(" Copied!");

    try {
        await copyTextToClipboard(textToCopy);
        const $original = $el.children().first().clone(true, true);
        $el.empty().append($successSpan);
        setTimeout(() => {
            $el.empty().append($original);
        }, 3000);
    } catch (error) {
        console.error("Failed to copy to clipboard:", error);
    }
}

/**
 * Selects the text content of the given element.
 * @param {jQuery|HTMLElement|Event} input - The element, jQuery object, or event.
 * @returns {jQuery} - The jQuery object of the selected element.
 */
export function selectText(input) {
    const $el = getJqElement(input || this).eq(0);
    const el = $el[0];
    if (document.body.createTextRange) {
        const range = document.body.createTextRange();
        range.moveToElementText(el);
        range.select();
    } else if (window.getSelection) {
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        sel.removeAllRanges();
        sel.addRange(range);
    }
    return $el;
}

/**
 * Gets the currently selected text in the document.
 * @returns {string} - The selected text.
 */
export function getSelectionText() {
    if (window.getSelection) {
        return window.getSelection().toString();
    } else if (document.selection && document.selection.type !== "Control") {
        return document.selection.createRange().text;
    }
    return "";
}

/**
 * Copies the currently selected text to the clipboard, or selects and copies text from the element if none is selected.
 * @param {jQuery|HTMLElement|Event} input - The element, jQuery object, or event.
 * @returns {Promise<void>}
 */
export async function copyToClipboard(input) {
    let $el = getJqElement(input || this).eq(0);
    selectText($el);
    let text = getSelectionText();
    if (text) {
        try {
            await copyTextToClipboard(text);
            selectText($el);
        } catch (error) {
            console.error("failed to copy text to clipboard :(", error);
        }
    }
}
