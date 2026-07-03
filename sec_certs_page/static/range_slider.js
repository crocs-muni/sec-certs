/**
 * range_slider.js
 *
 * Dual-thumb range sliders for any element with class="range-slider".
 *
 * Common data attributes:
 *   data-from   id of the "from" input   (required)
 *   data-to     id of the "to" input     (required)
 *   data-type   "date" (default) | "number"
 *
 * date mode — thumbs are years; writes ISO dates (YYYY-01-01 / YYYY-12-31) into
 * the bound (date) inputs, and reads the year back from them:
 *   data-min-year / data-min   minimum year (optional, else global default)
 *   data-max-year / data-max   maximum year (optional, else global default)
 *
 * number mode — thumbs are numbers; writes the raw number into the bound inputs:
 *   data-min    minimum value (required)
 *   data-max    maximum value (required)
 *   data-step   step          (optional, default 1)
 *
 * Usage:
 *   import { initRangeSliders, resetRangeSliders } from ".../range_slider.js";
 *
 *   initRangeSliders();                              // default year min/max
 *   initRangeSliders({ minYear: 2000, maxYear: 2030 });  // override date defaults
 *   resetRangeSliders();                             // from a reset handler
 */

const FALLBACK_MIN_YEAR = 1998;
const FALLBACK_MAX_YEAR = new Date().getFullYear();

// Global date-mode defaults — overridden by initRangeSliders options or per-element data attributes.
let globalMinYear = FALLBACK_MIN_YEAR;
let globalMaxYear = FALLBACK_MAX_YEAR;

function toPercent(v, min, max) {
    return ((v - min) / (max - min)) * 100;
}

function decimalsFromStep(step) {
    const s = String(step);
    const dot = s.indexOf(".");
    return dot === -1 ? 0 : s.length - dot - 1;
}

// Per-mode adapter: how to read the bound inputs, what to write back, and how to render labels.
function makeAdapter(container) {
    if ((container.dataset.type || "date") === "number") {
        const decimals = decimalsFromStep(container.dataset.step || "1");
        return {
            read: input => (input.value === "" ? null : parseFloat(input.value)),
            writeFrom: v => String(v),
            writeTo: v => String(v),
            label: v => v.toFixed(decimals),
        };
    }
    return {
        read: input => (input.value ? parseInt(input.value.slice(0, 4)) : null),
        writeFrom: v => `${v}-01-01`,
        writeTo: v => `${v}-12-31`,
        label: v => String(v),
    };
}

function bounds(container) {
    if ((container.dataset.type || "date") === "number") {
        return {
            min: parseFloat(container.dataset.min),
            max: parseFloat(container.dataset.max),
            step: parseFloat(container.dataset.step || "1"),
        };
    }
    const rawMin = container.dataset.minYear ?? container.dataset.min;
    const rawMax = container.dataset.maxYear ?? container.dataset.max;
    return {
        min: rawMin !== undefined ? parseInt(rawMin) : globalMinYear,
        max: rawMax !== undefined ? parseInt(rawMax) : globalMaxYear,
        step: 1,
    };
}

function buildSlider(container) {
    const { min, max, step } = bounds(container);
    const adapter = makeAdapter(container);

    container.innerHTML = `
        <div class="rs-wrap">
            <div class="rs-labels">
                <span class="rs-label-start"></span>
                <span class="rs-label-end"></span>
            </div>
            <div class="rs-track-wrap">
                <div class="rs-track-bg"></div>
                <div class="rs-track-fill"></div>
                <input class="rs-range rs-range-from" type="range"
                       min="${min}" max="${max}" step="${step}" value="${min}"
                       aria-label="From">
                <input class="rs-range rs-range-to" type="range"
                       min="${min}" max="${max}" step="${step}" value="${max}"
                       aria-label="To">
            </div>
            <div class="rs-edge-labels">
                <span>${adapter.label(min)}</span>
                <span>${adapter.label(max)}</span>
            </div>
        </div>`;

    const rangeFrom  = container.querySelector(".rs-range-from");
    const rangeTo    = container.querySelector(".rs-range-to");
    const fill       = container.querySelector(".rs-track-fill");
    const labelStart = container.querySelector(".rs-label-start");
    const labelEnd   = container.querySelector(".rs-label-end");
    const fromInput  = document.getElementById(container.dataset.from);
    const toInput    = document.getElementById(container.dataset.to);

    function values() {
        let lo = parseFloat(rangeFrom.value);
        let hi = parseFloat(rangeTo.value);
        if (lo > hi) { [lo, hi] = [hi, lo]; }
        return [lo, hi];
    }

    function updateFill() {
        const [lo, hi] = values();
        fill.style.left  = toPercent(lo, min, max) + "%";
        fill.style.width = (toPercent(hi, min, max) - toPercent(lo, min, max)) + "%";
        labelStart.textContent = adapter.label(lo);
        labelEnd.textContent   = adapter.label(hi);
    }

    function syncInputs() {
        const [lo, hi] = values();
        fromInput.value = adapter.writeFrom(lo);
        toInput.value   = adapter.writeTo(hi);
    }

    rangeFrom.addEventListener("input", function () {
        if (parseFloat(rangeFrom.value) > parseFloat(rangeTo.value)) {
            rangeTo.value = rangeFrom.value;
        }
        updateFill();
        syncInputs();
    });

    rangeTo.addEventListener("input", function () {
        if (parseFloat(rangeTo.value) < parseFloat(rangeFrom.value)) {
            rangeFrom.value = rangeTo.value;
        }
        updateFill();
        syncInputs();
    });

    // Init thumbs from existing input values (e.g. server-side pre-fill).
    const existingFrom = adapter.read(fromInput);
    const existingTo   = adapter.read(toInput);
    if (existingFrom !== null && existingFrom >= min && existingFrom <= max) {
        rangeFrom.value = existingFrom;
    }
    if (existingTo !== null && existingTo >= min && existingTo <= max) {
        rangeTo.value = existingTo;
    }
    updateFill();

    // Keep thumbs in sync when the bound inputs are changed manually.
    fromInput.addEventListener("change", function () {
        const v = adapter.read(fromInput);
        if (v !== null && v >= min && v <= max) {
            rangeFrom.value = v;
            if (parseFloat(rangeFrom.value) > parseFloat(rangeTo.value)) {
                rangeTo.value = rangeFrom.value;
            }
            updateFill();
        }
    });

    toInput.addEventListener("change", function () {
        const v = adapter.read(toInput);
        if (v !== null && v >= min && v <= max) {
            rangeTo.value = v;
            if (parseFloat(rangeTo.value) < parseFloat(rangeFrom.value)) {
                rangeFrom.value = rangeTo.value;
            }
            updateFill();
        }
    });
}

/**
 * Initialise all .range-slider elements in the document.
 *
 * @param {object} [options]
 * @param {number} [options.minYear]  Global minimum year for date-mode sliders (default: 1998).
 * @param {number} [options.maxYear]  Global maximum year for date-mode sliders (default: current year).
 */
export function initRangeSliders(options = {}) {
    if (options.minYear !== undefined) globalMinYear = options.minYear;
    if (options.maxYear !== undefined) globalMaxYear = options.maxYear;
    document.querySelectorAll(".range-slider").forEach(buildSlider);
}

/**
 * Reset all sliders to their full range and clear their bound inputs.
 */
export function resetRangeSliders() {
    document.querySelectorAll(".range-slider").forEach(function (container) {
        const rFrom = container.querySelector(".rs-range-from");
        const rTo   = container.querySelector(".rs-range-to");
        if (rFrom && rTo) {
            rFrom.value = rFrom.min;
            rTo.value   = rTo.max;
            rFrom.dispatchEvent(new Event("input"));
            const fromInput = document.getElementById(container.dataset.from);
            const toInput   = document.getElementById(container.dataset.to);
            if (fromInput) fromInput.value = "";
            if (toInput) toInput.value = "";
        }
    });
}
