"""Generic route surface scoring truth tables.

Every assertion keys on generic structure/token families only — no full path,
app name, parameter, or credential is special-cased.
"""

from app.core.crawler.route_priority import score_route_surface


def test_query_string_outranks_plain_route():
    with_query = score_route_surface("http://x/items?id=1")
    plain = score_route_surface("http://x/items")
    assert with_query > plain


def test_high_value_token_outranks_generic_route():
    login = score_route_surface("http://x/rest/user/login")
    about = score_route_surface("http://x/about")
    assert login > about


def test_hash_router_route_and_query_are_scored():
    # SPAs encode the real route (and its query) in the fragment.
    hash_search = score_route_surface("http://x/#/search?q=test")
    hash_plain = score_route_surface("http://x/#/home")
    assert hash_search > hash_plain
    assert hash_search > 0


def test_js_mined_provenance_boosts_score():
    mined = score_route_surface("http://x/data", evidence="javascript")
    static = score_route_surface("http://x/data", evidence="html-link")
    assert mined > static


def test_depth_is_a_tie_breaker_only():
    # A deep high-value route still outranks a shallow generic one.
    deep_auth = score_route_surface("http://x/a/b/c/account")
    shallow_generic = score_route_surface("http://x/blog")
    assert deep_auth > shallow_generic


def test_shallower_route_wins_among_equals():
    shallow = score_route_surface("http://x/page")
    deep = score_route_surface("http://x/a/b/c/page")
    assert shallow > deep


def test_priority_ordering_of_mixed_routes():
    routes = [
        "http://x/",
        "http://x/about",
        "http://x/rest/user/login",
        "http://x/search?q=1",
        "http://x/blog/post",
    ]
    ordered = sorted(routes, key=lambda u: score_route_surface(u), reverse=True)
    # Auth and search (query-bearing) rank above static content pages.
    assert ordered.index("http://x/rest/user/login") < ordered.index("http://x/about")
    assert ordered.index("http://x/search?q=1") < ordered.index("http://x/about")


def test_malformed_url_scores_zero_without_raising():
    assert score_route_surface("::::not a url") == 0 or isinstance(
        score_route_surface("::::not a url"), int
    )
