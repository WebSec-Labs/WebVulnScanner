"""Unit tests for crawler HTML link extractor."""

from unittest.mock import patch

from app.scanner.crawler.extractor import (
    HTMLAnchorExtractor,
    extract_links,
)


def test_extractor_class_direct_usage():
    """Verify HTMLAnchorExtractor class directly using streaming feed and close."""
    extractor = HTMLAnchorExtractor(max_links=10)
    extractor.feed('<a href="/stream-1">Part 1</a>')
    extractor.feed('<a href="/stream-2">Part 2</a>')
    extractor.close()
    assert extractor.links == ["/stream-1", "/stream-2"]


def test_extractor_basic_links():
    """Verify extraction of standard anchor and area links."""
    html = """
    <html>
        <body>
            <a href="/about">About Us</a>
            <a href="https://example.com/contact">Contact</a>
            <map name="workmap">
                <area href="/services" alt="Services">
            </map>
        </body>
    </html>
    """
    links = extract_links(html)
    assert links == ["/about", "https://example.com/contact", "/services"]


def test_extractor_canonical_link():
    """Verify that <link rel='canonical'> is extracted and non-canonical links are ignored."""
    html = """
    <head>
        <link rel="stylesheet" href="/style.css">
        <link rel="icon" href="/favicon.ico">
        <link rel="canonical" href="https://example.com/canonical-page">
        <link rel="alternate canonical" href="https://example.com/alt-canonical">
        <link rel="preload" href="/font.woff2" as="font">
    </head>
    """
    links = extract_links(html)
    assert links == [
        "https://example.com/canonical-page",
        "https://example.com/alt-canonical",
    ]


def test_extractor_case_insensitivity_and_unquoted_attributes():
    """Verify handling of uppercase tags and unquoted or single-quoted attributes."""
    html = """
    <A HREF=/unquoted>Unquoted</A>
    <a href='/single-quoted'>Single</a>
    <AREA HREF=/area-unquoted>
    <LINK REL="CANONICAL" HREF=/upper-canonical>
    """
    links = extract_links(html)
    assert links == ["/unquoted", "/single-quoted", "/area-unquoted", "/upper-canonical"]


def test_extractor_malformed_html_and_unclosed_tags():
    """Verify extractor handles unclosed anchor and paragraph tags."""
    html = """
    <div>
        <a href="/first">First Link without closing a tag
        <a href="/second">Second Link without closing a tag
        <a href="/third">Third Link
        <p>Text without closing p tag
        <a href="/fourth">Fourth</a>
    </div>
    """
    links = extract_links(html)
    assert links == ["/first", "/second", "/third", "/fourth"]


def test_extractor_unclosed_attribute_quotes():
    """Verify extractor does not crash on unclosed attribute quotes."""
    html = """
    <a href="/valid-1">Valid 1</a>
    <a href="/broken" title="unclosed quote>Broken
    <p>Next paragraph with quote: "</p>
    <a href="/valid-2">Valid 2</a>
    """
    links = extract_links(html)
    assert "/valid-1" in links
    assert "/valid-2" in links


def test_extractor_missing_bracket_recovery():
    """Verify extractor recovers gracefully from missing closing bracket."""
    html = """
    <a href="/broken" broken attribute
    <p>Intervening content</p>
    <a href="/recovered">Recovered</a>
    """
    links = extract_links(html)
    assert "/broken" in links
    assert "/recovered" in links


def test_extractor_comments_ignored():
    """Verify that commented-out HTML links are completely ignored."""
    html = """
    <a href="/visible">Visible</a>
    <!-- <a href="/hidden-in-comment">Commented Out</a> -->
    <!--
        <link rel="canonical" href="/comment-canonical">
        <area href="/comment-area">
    -->
    <a href="/visible-2">Visible 2</a>
    """
    links = extract_links(html)
    assert links == ["/visible", "/visible-2"]
    assert "/hidden-in-comment" not in links
    assert "/comment-canonical" not in links


def test_extractor_subresources_and_forms_excluded():
    """Verify that script, style, image, media, iframe, and form action URLs are excluded."""
    html = """
    <form action="/api/submit" method="POST">
        <input type="text" name="data">
        <button type="submit">Submit</button>
    </form>
    <img src="/images/logo.png" alt="Logo">
    <script src="/js/app.js"></script>
    <iframe src="/embedded/frame"></iframe>
    <video src="/media/video.mp4"></video>
    <audio src="/media/audio.mp3"></audio>
    <object data="/media/doc.pdf"></object>
    <embed src="/media/player.swf">
    <a href="/legitimate-link">Real Link</a>
    """
    links = extract_links(html)
    assert links == ["/legitimate-link"]
    assert "/api/submit" not in links
    assert "/images/logo.png" not in links
    assert "/js/app.js" not in links
    assert "/embedded/frame" not in links


def test_extractor_ignores_anchors_inside_script_or_style():
    """Verify that text resembling anchor tags inside script or style blocks is not extracted."""
    html = """
    <script>
        var fakeAnchor = '<a href="/script-leak">Fake</a>';
        var url = "/another-script-url";
    </script>
    <style>
        /* <a href="/style-leak">Style</a> */
    </style>
    <a href="/real-page">Real Page</a>
    """
    links = extract_links(html)
    assert links == ["/real-page"]


def test_extractor_duplicate_links_deterministic():
    """Verify deterministic deduplication preserving document appearance order."""
    html = """
    <a href="/page-1">First</a>
    <a href="/page-2">Second</a>
    <a href="/page-1">First Duplicate</a>
    <a href="/page-3">Third</a>
    <a href="/page-2">Second Duplicate</a>
    """
    links = extract_links(html)
    assert links == ["/page-1", "/page-2", "/page-3"]


def test_extractor_duplicate_attributes_on_same_tag():
    """Verify deterministic handling when multiple href attributes appear on a single tag."""
    html = '<a href="/first-attr" href="/second-attr">Multiple Attributes</a>'
    links = extract_links(html)
    assert links == ["/first-attr"]


def test_extractor_empty_and_whitespace_links_ignored():
    """Verify that empty, whitespace-only, or missing href attributes are safely ignored."""
    html = """
    <a>Anchor without href</a>
    <a href="">Empty string href</a>
    <a href="   ">Whitespace href</a>
    <a href="\t\n">Tab and newline href</a>
    <a href="/valid-target">Valid Target</a>
    """
    links = extract_links(html)
    assert links == ["/valid-target"]


def test_extractor_input_size_bounding():
    """Verify that HTML inputs exceeding max_html_chars are truncated before parsing."""
    padding = "<!-- " + ("A" * 1000) + " -->\n"
    html = padding + '<a href="/first">First</a>\n' + padding + '<a href="/second">Second</a>'

    # Set limit that allows /first but truncates before /second
    limit = len(padding) + len('<a href="/first">First</a>\n') + 10
    links = extract_links(html, max_html_chars=limit)
    assert "/first" in links
    assert "/second" not in links


def test_extractor_max_links_limit():
    """Verify that extraction halts once max_links unique links are reached."""
    html = "\n".join(f'<a href="/page-{i}">Link {i}</a>' for i in range(20))
    links = extract_links(html, max_links=5)
    assert len(links) == 5
    assert links == [f"/page-{i}" for i in range(5)]


def test_extractor_max_link_length_limit():
    """Verify that links exceeding max_link_length are safely skipped."""
    short_link = "/short"
    long_link = "/prefix/" + ("a" * 3000)
    html = f'<a href="{short_link}">Short</a><a href="{long_link}">Long</a>'

    links = extract_links(html, max_link_length=100)
    assert links == [short_link]


def test_extractor_bytes_input_handling():
    """Verify that bytes input is decoded safely without throwing errors."""
    html_bytes = b'<html><body><a href="/bytes-link">Bytes Link</a></body></html>'
    links = extract_links(html_bytes)
    assert links == ["/bytes-link"]


def test_extractor_no_network_calls():
    """Prove that extraction performs zero network operations or socket calls."""
    with patch("socket.socket") as mock_sock, patch("urllib.request.urlopen") as mock_url:
        links = extract_links('<a href="https://example.com/test">Test</a>')
        assert links == ["https://example.com/test"]
        mock_sock.assert_not_called()
        mock_url.assert_not_called()


def test_extractor_empty_input_returns_empty_list():
    """Verify that empty, None, or invalid inputs return an empty list safely."""
    assert extract_links("") == []
    assert extract_links(None) == []  # type: ignore[arg-type]
    assert extract_links(123) == []  # type: ignore[arg-type]
