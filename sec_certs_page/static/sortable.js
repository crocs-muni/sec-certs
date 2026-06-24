let userSorted = false;

export function isUserSorted() {
    return userSorted;
}

function cycleSortState(th, allowUnsorted) {
    const wasAsc  = th.classList.contains('sort-asc');
    const wasDesc = th.classList.contains('sort-desc');

    document.querySelectorAll('th.sortable')
        .forEach(h => h.classList.remove('sort-asc', 'sort-desc'));

    if (th.dataset.defaultSort === 'true' && !allowUnsorted) {
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

export function initSortable(onSort, allowUnsorted = () => false) {
    document.querySelectorAll('th.sortable').forEach(th => {
        const fresh = th.cloneNode(true);
        th.replaceWith(fresh);
        fresh.addEventListener('click', () => {
            userSorted = true;
            cycleSortState(fresh, allowUnsorted());
            onSort();
        });
    });
}
