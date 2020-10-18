STOP_ON_UNEXPECTED_NUMS = False
EXPECTED_CERTS_REFERENCED_ONCE = 942
EXPECTED_CERTS_MIN_ITEMS_FOUND_CSV = 4415
EXPECTED_CERTS_MIN_ITEMS_FOUND_HTML = 4413
EXPECTED_CERTS_MIN_ITEMS_FOUND_KEYWORDS = 494655
EXPECTED_CERTS_MIN_ITEMS_FOUND_FRONTPAGE = 1438
EXPECTED_PP_MIN_ITEMS_FOUND_CSV = 1000
EXPECTED_PP_MIN_ITEMS_FOUND_HTML = 1000
EXPECTED_PP_MIN_ITEMS_FOUND_KEYWORDS = 1000
EXPECTED_PP_MIN_ITEMS_FOUND_FRONTPAGE = 1000


def check_and_handle(expected, obtained, message):
    if expected != obtained:
        print('SANITY: {}: {} vs. {} expected'.format(message, expected, obtained))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')


def check_certs_referenced_once(num_items):
    check_and_handle(EXPECTED_CERTS_REFERENCED_ONCE, num_items, 'Different than expected num certificates referenced at least once')


def check_certs_min_items_found_csv(num_items):
    check_and_handle(EXPECTED_CERTS_MIN_ITEMS_FOUND_CSV, num_items, 'Different than expected number of CSV records found!')


def check_certs_min_items_found_html(num_items):
    check_and_handle(EXPECTED_CERTS_MIN_ITEMS_FOUND_HTML, num_items, 'Different than expected number of HTML records found!')


def check_certs_min_items_found_frontpage(num_items):
    check_and_handle(EXPECTED_CERTS_MIN_ITEMS_FOUND_FRONTPAGE, num_items, 'Different than expected number of frontpage records found!')


def check_certs_min_items_found_keywords(num_items):
    check_and_handle(EXPECTED_CERTS_MIN_ITEMS_FOUND_KEYWORDS, num_items, 'Different than expected number of keywords found!')


def check_pp_min_items_found_csv(num_items):
    check_and_handle(EXPECTED_PP_MIN_ITEMS_FOUND_CSV, num_items, 'Different than expected number of CSV records found!')


def check_pp_min_items_found_html(num_items):
    check_and_handle(EXPECTED_PP_MIN_ITEMS_FOUND_HTML, num_items, 'Different than expected number of HTML records found!')


def check_pp_min_items_found_frontpage(num_items):
    check_and_handle(EXPECTED_PP_MIN_ITEMS_FOUND_FRONTPAGE, num_items, 'Different than expected number of frontpage records found!')


def check_pp_min_items_found_keywords(num_items):
    check_and_handle(EXPECTED_PP_MIN_ITEMS_FOUND_KEYWORDS, num_items, 'Different than expected number of keywords found!')