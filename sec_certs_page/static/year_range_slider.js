/**
 * year-range-slider.js
 *
 * Initialises dual-thumb year range sliders for any element with
 * class="year-range-slider" and the following data attributes:
 *
 *   data-from="id-of-date-from-input"   (required)
 *   data-to="id-of-date-to-input"       (required)
 *   data-min-year="1990"                (optional, overrides global default)
 *   data-max-year="2030"                (optional, overrides global default)
 *
 * Usage:
 *   import { initYearRangeSliders, resetYearRangeSliders } from ".../year-range-slider.js";
 *
 *   // Default min/max used when no data attributes are present:
 *   initYearRangeSliders();
 *
 *   // Override global defaults (still overridden per-element by data attributes):
 *   initYearRangeSliders({ minYear: 2000, maxYear: 2030 });
 *
 *   // Reset all sliders (call from a reset handler):
 *   resetYearRangeSliders();
 */

const FALLBACK_MIN = 1998;
const FALLBACK_MAX = new Date().getFullYear();

// Global defaults — overridden by initYearRangeSliders options or per-element data attributes.
let globalMin = FALLBACK_MIN;
let globalMax = FALLBACK_MAX;

function yearToPercent(y, minYear, maxYear) {
    return ((y - minYear) / (maxYear - minYear)) * 100;
}

function buildSlider(container) {
    const fromId = container.dataset.from;
    const toId   = container.dataset.to;

    // Per-element overrides take priority, then global defaults.
    const minYear = container.dataset.minYear ? parseInt(container.dataset.minYear) : globalMin;
    const maxYear = container.dataset.maxYear ? parseInt(container.dataset.maxYear) : globalMax;

    container.innerHTML = `
        <div class="yrs-wrap">
            <div class="yrs-labels">
                <span class="yrs-label-start"></span>
                <span class="yrs-label-end"></span>
            </div>
            <div class="yrs-track-wrap">
                <div class="yrs-track-bg"></div>
                <div class="yrs-track-fill"></div>
                <input class="yrs-range yrs-range-from" type="range"
                       min="${minYear}" max="${maxYear}" step="1" value="${minYear}"
                       aria-label="Year from">
                <input class="yrs-range yrs-range-to" type="range"
                       min="${minYear}" max="${maxYear}" step="1" value="${maxYear}"
                       aria-label="Year to">
            </div>
            <div class="yrs-edge-labels">
                <span>${minYear}</span>
                <span>${maxYear}</span>
            </div>
        </div>`;

    const rangeFrom  = container.querySelector(".yrs-range-from");
    const rangeTo    = container.querySelector(".yrs-range-to");

    const fill       = container.querySelector(".yrs-track-fill");
    const labelStart = container.querySelector(".yrs-label-start");
    const labelEnd   = container.querySelector(".yrs-label-end");
    const dateFrom   = document.getElementById(fromId);
    const dateTo     = document.getElementById(toId);

    function pct(y) { return yearToPercent(y, minYear, maxYear); }

    function updateFill() {
        let lo = parseInt(rangeFrom.value);
        let hi = parseInt(rangeTo.value);
        if (lo > hi) { [lo, hi] = [hi, lo]; }
        fill.style.left  = pct(lo) + "%";
        fill.style.width = (pct(hi) - pct(lo)) + "%";
        labelStart.textContent = lo;
        labelEnd.textContent   = hi;
    }

    function syncDates() {
        let lo = parseInt(rangeFrom.value);
        let hi = parseInt(rangeTo.value);
        if (lo > hi) { [lo, hi] = [hi, lo]; }
        dateFrom.value = lo + "-01-01";
        dateTo.value   = hi + "-12-31";
    }

    rangeFrom.addEventListener("input", function () {
        if (parseInt(rangeFrom.value) > parseInt(rangeTo.value)) {
            rangeTo.value = rangeFrom.value;
        }
        updateFill();
        syncDates();
    });

    rangeTo.addEventListener("input", function () {
        if (parseInt(rangeTo.value) < parseInt(rangeFrom.value)) {
            rangeFrom.value = rangeTo.value;
        }
        updateFill();
        syncDates();
    });

    // Init from existing date field values (e.g. server-side pre-fill).
    const existingFrom = dateFrom.value ? parseInt(dateFrom.value.slice(0, 4)) : null;
    const existingTo   = dateTo.value   ? parseInt(dateTo.value.slice(0, 4))   : null;
    if (existingFrom && existingFrom >= minYear && existingFrom <= maxYear) {
        rangeFrom.value = existingFrom;
    }
    if (existingTo && existingTo >= minYear && existingTo <= maxYear) {
        rangeTo.value = existingTo;
    }
    updateFill();

    // Keep sliders in sync when date inputs are changed manually.
    dateFrom.addEventListener("change", function () {
        const y = parseInt(dateFrom.value.slice(0, 4));
        if (y >= minYear && y <= maxYear) {
            rangeFrom.value = y;
            if (parseInt(rangeFrom.value) > parseInt(rangeTo.value)) {
                rangeTo.value = rangeFrom.value;
            }
            updateFill();
        }
    });

    dateTo.addEventListener("change", function () {
        const y = parseInt(dateTo.value.slice(0, 4));
        if (y >= minYear && y <= maxYear) {
            rangeTo.value = y;
            if (parseInt(rangeTo.value) < parseInt(rangeFrom.value)) {
                rangeFrom.value = rangeTo.value;
            }
            updateFill();
        }
    });
}

/**
 * Initialise all .year-range-slider elements in the document.
 *
 * @param {object} [options]
 * @param {number} [options.minYear]  Global minimum year (default: 1998).
 *                                    Overridden per element by data-min-year.
 * @param {number} [options.maxYear]  Global maximum year (default: current year).
 *                                    Overridden per element by data-max-year.
 */
export function initYearRangeSliders(options = {}) {
    if (options.minYear !== undefined) globalMin = options.minYear;
    if (options.maxYear !== undefined) globalMax = options.maxYear;
    document.querySelectorAll(".year-range-slider").forEach(buildSlider);
}

/**
 * Reset all sliders to their full year range and clear their date fields.
 */
export function resetYearRangeSliders() {
    document.querySelectorAll(".year-range-slider").forEach(function (container) {
        const rFrom = container.querySelector(".yrs-range-from");
        const rTo   = container.querySelector(".yrs-range-to");
        if (rFrom && rTo) {
            rFrom.value = rFrom.min;
            rTo.value   = rTo.max;
            rFrom.dispatchEvent(new Event("input"));
            document.getElementById(container.dataset.from).value = '';
            document.getElementById(container.dataset.to).value   = '';
        }
    });
}
