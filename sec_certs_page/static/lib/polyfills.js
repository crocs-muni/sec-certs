// Polyfill for Array.prototype.at (ES2022)
// Required for older browsers (e.g. Chrome < 92) that do not support it.
if (!Array.prototype.at) {
    Array.prototype.at = function(index) {
        index = Math.trunc(index) || 0;
        if (index < 0) index += this.length;
        if (index < 0 || index >= this.length) return undefined;
        return this[index];
    };
}