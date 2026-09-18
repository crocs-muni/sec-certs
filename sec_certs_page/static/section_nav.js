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
const RELEASE_RATIO = 0.35;
const RELEASE_SPAN_RATIO = 0.6;
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
    const maxScrollTop = () => Math.max(0, document.documentElement.scrollHeight - window.innerHeight);

    const activationPoints = () => {
        const maxScroll = maxScrollTop();
        const points = items.map((item) => item.section.getBoundingClientRect().top + window.scrollY - offset);
        const tail = points.findIndex((point) => point > maxScroll);
        if (tail !== -1) {
            const start = tail === 0 ? 0 : points[tail - 1];
            // One gap more than there are tail sections, so the last one activates a gap
            // before the end of the document rather than exactly at it -- otherwise it holds
            // only while pinned at the bottom and gives it up on the first pixel scrolled up.
            const gap = Math.min(TAIL_GAP, (maxScroll - start) / (points.length - tail + 1));
            for (let i = tail; i < points.length; i++) {
                points[i] = Math.min(points[i], maxScroll - gap * (points.length - i));
            }
        }
        return points;
    };

    /**
     * The section the scroll position falls in, taking each section's own activation point at
     * face value.
     * @param {number[]} points - Activation points, ascending.
     * @param {number} scrollY - Current scroll position.
     * @returns {number} - Index of the section owning that position.
     */
    const positionIndex = (points, scrollY) => {
        let index = 0;
        points.forEach((point, i) => {
            if (scrollY >= point - TOLERANCE) {
                index = i;
            }
        });
        return index;
    };

    /**
     * Which section to highlight, asymmetrically.
     *
     * Downwards a section takes over as its heading comes to rest under the navbar, which is
     * the moment it starts being read. Upwards that same line would hand back the instant the
     * heading dips below the navbar, when the previous section is only a sliver at the top of
     * the screen and the one being left still fills it — so a section holds the highlight
     * until the previous one is genuinely back on screen. It is then given back one section at
     * a time, never two, however fast the page is moving; update() keeps asking until the
     * highlight has caught up with the scroll position.
     * @returns {number} - Index of the section to highlight.
     */
    const currentIndex = () => {
        // Nothing to scroll means every section is on screen at once and every activation
        // point collapses to 0, which would otherwise pick the last one.
        if (maxScrollTop() === 0) {
            return 0;
        }
        const scrollY = window.scrollY;
        const points = activationPoints();
        const index = positionIndex(points, scrollY);
        if (index >= activeIndex || activeIndex < 1) {
            return index;
        }
        const span = points[activeIndex] - points[activeIndex - 1];
        const release = Math.min(RELEASE_RATIO * window.innerHeight, span * RELEASE_SPAN_RATIO);
        if (scrollY > points[activeIndex] - release) {
            return activeIndex;
        }
        return activeIndex - 1;
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
        if (pinned) {
            return;
        }
        activate(currentIndex());
        // Giving the highlight back one section per frame can lag a fast scroll, and the
        // scroll may stop before it has caught up, so drive the remaining steps ourselves.
        if (activeIndex !== positionIndex(activationPoints(), window.scrollY)) {
            onScroll();
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
    // Expanding a collapsed list or loading the reference graph changes the document height
    // without either event, which would leave the footer offset and activation points stale.
    if (typeof ResizeObserver !== "undefined") {
        new ResizeObserver(onScroll).observe(document.body);
    }
    update();
}
