/**
 * Scroll-driven highlighting of the entry page section navigation.
 *
 * Replaces Bootstrap's ScrollSpy, which activates the *lowest* section visible in its
 * detection band. With short sections that makes the middle ones unpickable, and it can
 * highlight nothing at all at the top of the page or near its end.
 */

const NAVBAR_HEIGHT = 57;
const SETTLE_DELAY = 150;
const TOLERANCE = 1;

/**
 * Collects the nav links that point at an existing section, in document order.
 * @param {HTMLElement} nav - The navigation container.
 * @returns {{link: HTMLAnchorElement, section: HTMLElement}[]} - The link/section pairs.
 */
function collectItems(nav) {
    const items = [];
    for (const link of nav.querySelectorAll("a[href^='#']")) {
        const section = document.getElementById(decodeURIComponent(link.hash.slice(1)));
        if (section) {
            items.push({link, section});
        }
    }
    return items.sort((a, b) => a.section.offsetTop - b.section.offsetTop);
}

/**
 * Highlights section links in a side navigation based on the scroll position.
 *
 * The heading of a card is what decides, and only ever in the direction being scrolled:
 * going down, a section takes over once its heading passes up under the navbar; going
 * back up, a section takes over once its heading reappears below the navbar, so the
 * previous one stays highlighted while its own heading is off screen. Two positions are
 * absolute: at the top of the page the first item is active, and at the very bottom the
 * last one is, since short trailing sections can never reach the navbar. Clicking a link
 * pins it until scrolling settles, so a jump the page cannot fully perform still leaves
 * the clicked section highlighted.
 *
 * @param {string} navSelector - Selector of the navigation container.
 * @param {number} offset - Height of the fixed navbar that headings are measured against.
 * @returns {void}
 */
export function initSectionNav(navSelector = "#left-navigation", offset = NAVBAR_HEIGHT) {
    const nav = document.querySelector(navSelector);
    if (!nav) {
        return;
    }
    const items = collectItems(nav);
    if (!items.length) {
        return;
    }

    let activeIndex = -1;
    let lastScrollY = window.scrollY;
    let pinned = false;
    let settleTimer = null;
    let queued = false;

    const activate = (index) => {
        activeIndex = index;
        items.forEach((item, i) => {
            item.link.classList.toggle("active", i === index);
            if (i === index) {
                item.link.setAttribute("aria-current", "true");
            } else {
                item.link.removeAttribute("aria-current");
            }
        });
    };

    const targetIndex = (scrollsDown) => {
        const scrollable = document.documentElement;
        if (window.scrollY + window.innerHeight >= scrollable.scrollHeight - 2) {
            return items.length - 1;
        }
        if (window.scrollY <= 0) {
            return 0;
        }
        const tops = items.map((item) => item.section.getBoundingClientRect().top);
        if (scrollsDown) {
            // The last heading that has passed under the navbar, never moving back up.
            let index = Math.max(activeIndex, 0);
            tops.forEach((top, i) => {
                if (top <= offset + TOLERANCE && i > index) {
                    index = i;
                }
            });
            return index;
        }
        // The topmost heading that is back on screen, never moving back down.
        const reappeared = tops.findIndex((top) => top >= offset - TOLERANCE);
        if (reappeared === -1) {
            return Math.max(activeIndex, 0);
        }
        return activeIndex === -1 ? reappeared : Math.min(activeIndex, reappeared);
    };

    const settle = () => {
        lastScrollY = window.scrollY;
        clearTimeout(settleTimer);
        settleTimer = setTimeout(() => {
            pinned = false;
        }, SETTLE_DELAY);
    };

    const update = () => {
        queued = false;
        const scrollsDown = window.scrollY >= lastScrollY;
        lastScrollY = window.scrollY;
        activate(targetIndex(scrollsDown));
    };

    const onScroll = () => {
        // The jump caused by a nav click must not move the highlight off the clicked item.
        if (pinned) {
            settle();
            return;
        }
        if (!queued) {
            queued = true;
            requestAnimationFrame(update);
        }
    };

    nav.addEventListener("click", (event) => {
        const link = event.target.closest("a[href^='#']");
        const index = link ? items.findIndex((item) => item.link === link) : -1;
        if (index === -1) {
            return;
        }
        pinned = true;
        activate(index);
        settle();
    });

    window.addEventListener("scroll", onScroll, {passive: true});
    window.addEventListener("resize", onScroll, {passive: true});
    update();
}
