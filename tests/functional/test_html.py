from sec_certs_page.common.html import clean_css


def test_clean_css():
    css = """
    .test1, .test3 {
        color: red;
    }
    .test2 {
        color: blue;
    }
    """

    html = """
    <a class="test1 some-other-cls">test</a>
    """

    res_css = clean_css(css, html)
    print(res_css)
    assert "test1" in res_css
    assert "test2" not in res_css
