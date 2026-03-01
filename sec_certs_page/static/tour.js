$(function () {
    const driver = window.driver.js.driver;
    const tourTrigger = $('#tour-trigger');
    const tourWrapper = $('#tour-trigger-wrapper');

    if (window.tourSteps && window.tourSteps.length > 0) {
        // Enable the button if steps are defined for this page
        tourTrigger.prop('disabled', false);

        const tour = driver({
            showProgress: true,
            steps: window.tourSteps
        });

        tourTrigger.on('click', function (e) {
            e.preventDefault();
            tour.drive();
        });

        // Auto-start tour if requested via URL
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('tour') === 'start') {
            const newUrl = window.location.pathname;
            window.history.replaceState({}, document.title, newUrl);
            tour.drive();
        }
    } else {
        // Update tooltip for disabled state
        tourWrapper.attr('data-bs-title', 'No tour available for this page');
        // Re-initialize tooltip to reflect the new title
        const tooltip = bootstrap.Tooltip.getInstance(tourWrapper[0]);
        if (tooltip) {
            tooltip.dispose();
        }
        new bootstrap.Tooltip(tourWrapper[0]);
    }
});
