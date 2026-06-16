function cycleSortState(th) {
    const wasAsc  = th.classList.contains('sort-asc');
    const wasDesc = th.classList.contains('sort-desc');

    document.querySelectorAll('th.sortable')
        .forEach(h => h.classList.remove('sort-asc', 'sort-desc'));

    // The default column is always sorted by the server (empty/match-all search),
    // so an "unsorted" state is meaningless: toggle asc <-> desc only.
    if (th.dataset.defaultSort === 'true') {
        th.classList.add(wasAsc ? 'sort-desc' : 'sort-asc');
        return;
    }

    if (!wasAsc && !wasDesc) {
        th.classList.add('sort-asc');
    } else if (wasAsc) {
        th.classList.add('sort-desc');
    }
}

export function setSort(col, order) {
    document.querySelectorAll('th.sortable')
        .forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    if (!col || !order) return;
    document.querySelector(`th[data-col="${col}"]`)
        ?.classList.add(order === 'asc' ? 'sort-asc' : 'sort-desc');
}

export function initSortable(onSort) {
    document.querySelectorAll('th.sortable').forEach(th => {
        const fresh = th.cloneNode(true);
        th.replaceWith(fresh);
        fresh.addEventListener('click', () => {
            cycleSortState(fresh);
            onSort();
        });
    });
}
