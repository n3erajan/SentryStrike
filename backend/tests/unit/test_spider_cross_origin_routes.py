from app.core.crawler.models import CrawlState, RouteCandidate, RouteSource
from app.core.crawler.spider import FormInput, HtmlForm, WebSpider, normalize_for_dedupe, same_domain


def merge_browser_routes(root_url: str, discovered_urls: list[str], crawl_state: CrawlState) -> list[str]:
    seen = {normalize_for_dedupe(u) for u in discovered_urls}
    for route in crawl_state.routes:
        if getattr(route, "is_dead", False):
            continue
        if route.source not in (RouteSource.browser,):
            continue
        if not same_domain(root_url, route.url):
            continue
        if "?" not in route.url:
            continue

        normalized = normalize_for_dedupe(route.url)
        if normalized not in seen:
            seen.add(normalized)
            discovered_urls.append(route.url)

    return discovered_urls


def test_browser_routes_skip_cross_origin_redirect_targets():
    root_url = "http://localhost:3000"
    discovered_urls = [root_url]
    crawl_state = CrawlState()

    crawl_state.routes.append(
        RouteCandidate(
            url="https://github.com/juice-shop/juice-shop#/",
            source=RouteSource.browser,
            priority=75,
            depth=0,
        )
    )
    crawl_state.routes.append(
        RouteCandidate(
            url="http://localhost:3000/redirect?to=https://github.com/juice-shop/juice-shop#/",
            source=RouteSource.browser,
            priority=75,
            depth=0,
        )
    )

    merged = merge_browser_routes(root_url, discovered_urls, crawl_state)

    assert "https://github.com/juice-shop/juice-shop#/" not in merged
    assert (
        "http://localhost:3000/redirect?to=https://github.com/juice-shop/juice-shop#/"
        in merged
    )


def test_browser_forms_are_merged_into_detector_forms_same_origin_only():
    html_form = HtmlForm(
        page_url="http://localhost:3000/contact",
        action="http://localhost:3000/api/Feedbacks",
        method="POST",
        inputs=[FormInput("comment", "text")],
    )
    browser_forms = [
        {
            "page_url": "http://localhost:3000/profile",
            "action": "http://localhost:3000/api/Users",
            "method": "POST",
            "inputs": [
                {"name": "email", "type": "email"},
                {"name": "password", "type": "password"},
            ],
        },
        {
            "page_url": "http://localhost:3000/upload",
            "action": "http://localhost:3000/api/ProfileImage",
            "method": "POST",
            "inputs": [
                {"name": "", "type": "file"},
                {"name": "userId", "type": "hidden"},
            ],
        },
        {
            "page_url": "http://localhost:3000/external",
            "action": "https://example.org/collect",
            "method": "POST",
            "inputs": [{"name": "event", "type": "text"}],
        },
    ]

    merged = WebSpider._merge_browser_forms(
        "http://localhost:3000/",
        [html_form],
        browser_forms,
    )

    assert [form.action for form in merged] == [
        "http://localhost:3000/api/Feedbacks",
        "http://localhost:3000/api/Users",
        "http://localhost:3000/api/ProfileImage",
    ]
    upload_form = merged[2]
    assert [(inp.name, inp.input_type) for inp in upload_form.inputs] == [
        ("file", "file"),
        ("userId", "hidden"),
    ]


def test_synthetic_named_inputs_are_dropped_during_merge():
    # Pre-hydration Angular captures yield positional fallback names
    # (field_<cid>_<idx>) flagged named=False. These are internal handles for
    # fill/submit addressing, never real backend parameter names — they must
    # not become injection targets. Real-named inputs in the same cluster
    # survive.
    browser_forms = [
        {
            "page_url": "http://localhost:3000/complain",
            "action": "http://localhost:3000/api/Complaints",
            "method": "POST",
            "inputs": [
                {"name": "message", "type": "textarea", "named": True},
                {"name": "field_1_0", "type": "text", "named": False},
                {"name": "field_1_1", "type": "text", "named": False},
            ],
        },
    ]

    merged = WebSpider._merge_browser_forms(
        "http://localhost:3000/",
        [],
        browser_forms,
    )

    assert len(merged) == 1
    assert [inp.name for inp in merged[0].inputs] == ["message"]
