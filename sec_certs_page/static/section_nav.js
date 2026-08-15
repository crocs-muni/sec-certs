/**
 * Scroll-driven highlighting of the entry page section navigation, and keeping it clear of
 * the footer.
 *
 * Replaces Bootstrap's ScrollSpy, which activates the *lowest* section visible in its
 * detection band. With short sections that makes the middle ones unpickable, and it can
 * highlight nothing at all at the top of the page or near its end.
 */

const NAVBAR_HEIGHT = 57;
const SETTLE_DELAY = 150;
const TOLERANCE = 1;
const TAIL_GAP = 60;
const FOOTER_GAP = 16;

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
 * Each section owns the scroll position at which its heading comes to rest under the
 * navbar, and the one whose position was passed last is highlighted. Asking where the page
 * *is* rather than which heading is currently under the navbar keeps the sequence identical
 * in both directions, and gives short sections sharing a screen their own turn. Clicking a
 * link pins it until scrolling settles, so a jump the page cannot fully perform still
 * leaves the clicked section highlighted.
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
    const footer = document.querySelector("footer");
    const lastLink = items[items.length - 1].link;

    let activeIndex = -1;
    let shift = 0;
    let pinned = false;
    let settleTimer = null;
    let queued = false;

    const activate = (index) => {
        if (index === activeIndex) {
            return;
        }
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

    /**
     * The scroll position that activates each section, in document order. The sections at
     * the end of the page cannot reach theirs — the document runs out of scroll before
     * their heading gets to the navbar — so they are pulled back from the end of the page,
     * one gap apart, only as far as they must move: enough to give each its own turn
     * instead of being skipped in favour of the last one, while the ones that fit keep
     * activating where their heading actually arrives.
     * @returns {number[]} - One scroll position per section, ascending.
     */
    const activationPoints = () => {
        const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
        const points = items.map((item) => item.section.getBoundingClientRect().top + window.scrollY - offset);
        const tail = points.findIndex((point) => point > maxScroll);
        if (tail !== -1) {
            const start = tail === 0 ? 0 : points[tail - 1];
            const gap = Math.min(TAIL_GAP, (maxScroll - start) / (points.length - tail));
            for (let i = tail; i < points.length; i++) {
                points[i] = Math.min(points[i], maxScroll - gap * (points.length - 1 - i));
            }
        }
        return points;
    };

    const currentIndex = () => {
        const scrollY = window.scrollY;
        let index = 0;
        activationPoints().forEach((point, i) => {
            if (scrollY >= point - TOLERANCE) {
                index = i;
            }
        });
        return index;
    };

    /**
     * The footer paints over the navigation, so once it reaches the last link the
     * navigation is moved up out of its way and scrolls along with the rest of the page —
     * the heading and the first sections leaving under the navbar, the ones nearest the
     * footer staying readable. Only the links are measured, not the box around them, which
     * is a whole viewport tall and mostly empty. Undoing the shift we applied last time
     * keeps the measurement independent of the current one.
     * @returns {void}
     */
    const clearFooter = () => {
        if (!footer) {
            return;
        }
        const restingBottom = lastLink.getBoundingClientRect().bottom - shift;
        shift = Math.round(Math.min(0, footer.getBoundingClientRect().top - FOOTER_GAP - restingBottom));
        nav.style.transform = shift ? `translateY(${shift}px)` : "";
    };

    const settle = () => {
        clearTimeout(settleTimer);
        settleTimer = setTimeout(() => {
            pinned = false;
        }, SETTLE_DELAY);
    };

    const update = () => {
        queued = false;
        clearFooter();
        if (!pinned) {
            activate(currentIndex());
        }
    };

    const onScroll = () => {
        // The jump caused by a nav click must not move the highlight off the clicked item.
        if (pinned) {
            settle();
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
