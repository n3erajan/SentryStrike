"""Resolving WordPress plugin/theme slugs and versions from asset URLs.

The Wordfence feed is keyed on slug, so without one every plugin and theme stays
unassessed no matter how good the client is. WordPress enqueues extension assets
from predictable paths - ``/wp-content/plugins/<slug>/...`` - and usually stamps
them with the extension's own version, which is where both facts come from.
"""

from app.integrations.wordpress_assets import extract_extensions


def _slugs(components) -> dict[str, tuple[str, str | None]]:
    return {c.slug: (c.category, c.version) for c in components}


# --------------------------------------------------------------------------- #
# Slug + version extraction
# --------------------------------------------------------------------------- #

def test_plugin_slug_and_version_are_read_from_the_asset_path() -> None:
    html = """
    <link rel='stylesheet' href='https://t.test/wp-content/plugins/smart-slider-3/css/app.css?ver=3.5.1'>
    """
    [component] = extract_extensions(html, [])

    assert component.slug == "smart-slider-3"
    assert component.version == "3.5.1"
    assert component.category == "wordpress plugins"
    assert component.name == "Smart Slider 3"


def test_theme_assets_are_categorised_as_themes() -> None:
    html = "<link href='/wp-content/themes/astra/style.css?ver=4.1.0' rel='stylesheet'>"
    [component] = extract_extensions(html, [])

    assert component.slug == "astra"
    assert component.category == "wordpress themes"
    assert component.version == "4.1.0"


def test_must_use_plugins_are_treated_as_plugins() -> None:
    html = "<script src='/wp-content/mu-plugins/some-loader/js/a.js?ver=1.2.0'></script>"
    [component] = extract_extensions(html, [])

    assert component.slug == "some-loader"
    assert component.category == "wordpress plugins"


def test_script_src_list_is_searched_as_well_as_html() -> None:
    components = extract_extensions("", ["/wp-content/plugins/contact-form-7/js/x.js?ver=5.9.3"])

    assert _slugs(components) == {"contact-form-7": ("wordpress plugins", "5.9.3")}


def test_assets_without_a_version_still_yield_the_slug() -> None:
    """Knowing a plugin is installed is useful even when its version is unknown."""
    html = "<link href='/wp-content/plugins/akismet/style.css' rel='stylesheet'>"
    [component] = extract_extensions(html, [])

    assert component.slug == "akismet"
    assert component.version is None


# --------------------------------------------------------------------------- #
# Version strings that are not versions
# --------------------------------------------------------------------------- #

def test_cache_busting_hashes_are_not_mistaken_for_versions() -> None:
    """Real values seen in production: ``1c12b24c`` and a 32-char md5."""
    html = """
    <link href='/wp-content/plugins/a-plugin/a.css?ver=1c12b24c' rel='stylesheet'>
    <link href='/wp-content/plugins/b-plugin/b.css?ver=63f88ce23ad1462e96e1ca50e55dda1f' rel='stylesheet'>
    """
    components = extract_extensions(html, [])

    assert _slugs(components) == {
        "a-plugin": ("wordpress plugins", None),
        "b-plugin": ("wordpress plugins", None),
    }


def test_a_version_equal_to_wordpress_core_is_discarded_as_ambiguous() -> None:
    """WordPress stamps ``?ver=<core version>`` when a plugin declares none.

    Treating that as the plugin's version would query the feed for, say, Akismet
    7.1 - a version that does not exist - and match whatever range happens to
    contain it.
    """
    html = "<link href='/wp-content/plugins/akismet/a.css?ver=7.1' rel='stylesheet'>"
    [component] = extract_extensions(html, [], core_version="7.1")

    assert component.slug == "akismet"
    assert component.version is None


def test_a_version_differing_from_core_is_kept() -> None:
    html = "<link href='/wp-content/plugins/akismet/a.css?ver=5.3.2' rel='stylesheet'>"
    [component] = extract_extensions(html, [], core_version="7.1")

    assert component.version == "5.3.2"


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #

def test_one_component_per_slug_even_across_many_assets() -> None:
    html = """
    <link href='/wp-content/plugins/woocommerce/a.css?ver=8.6.1' rel='stylesheet'>
    <script src='/wp-content/plugins/woocommerce/b.js?ver=8.6.1'></script>
    <script src='/wp-content/plugins/woocommerce/c.js'></script>
    """
    components = extract_extensions(html, [])

    assert _slugs(components) == {"woocommerce": ("wordpress plugins", "8.6.1")}


def test_a_version_bearing_asset_wins_over_a_version_less_one() -> None:
    html = """
    <script src='/wp-content/plugins/jetpack/no-version.js'></script>
    <script src='/wp-content/plugins/jetpack/versioned.js?ver=13.1'></script>
    """
    [component] = extract_extensions(html, [])

    assert component.version == "13.1"


def test_a_plugin_and_a_theme_sharing_a_slug_stay_separate() -> None:
    html = """
    <link href='/wp-content/plugins/shared/a.css?ver=1.0' rel='stylesheet'>
    <link href='/wp-content/themes/shared/b.css?ver=2.0' rel='stylesheet'>
    """
    components = extract_extensions(html, [])

    assert sorted((c.slug, c.category, c.version) for c in components) == [
        ("shared", "wordpress plugins", "1.0"),
        ("shared", "wordpress themes", "2.0"),
    ]


# --------------------------------------------------------------------------- #
# Non-WordPress input
# --------------------------------------------------------------------------- #

def test_a_page_with_no_wp_content_assets_yields_nothing() -> None:
    assert extract_extensions("<script src='/static/app.js?ver=1.0'></script>", []) == []
    assert extract_extensions("", []) == []


def test_wp_includes_core_assets_are_not_extensions() -> None:
    """``/wp-includes/`` is core, already covered by the CPE path."""
    html = "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>"

    assert extract_extensions(html, []) == []


def test_slugs_that_are_path_traversal_or_empty_are_rejected() -> None:
    html = """
    <link href='/wp-content/plugins//a.css?ver=1.0' rel='stylesheet'>
    <link href='/wp-content/plugins/../evil/a.css?ver=1.0' rel='stylesheet'>
    """

    assert extract_extensions(html, []) == []
