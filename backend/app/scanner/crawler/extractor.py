"""HTML link extractor for bounded, safe web crawling.

Parses static HTML using Python's standard-library html.parser.HTMLParser.
Extracts navigational links (<a href>, <area href>, and <link rel="canonical" href>)
without executing JavaScript, submitting forms, or making network requests.
"""

from collections.abc import Iterable
from html.parser import HTMLParser

DEFAULT_MAX_HTML_CHARS = 1_000_000  # 1 MB character cap
DEFAULT_MAX_LINKS = 500  # Maximum number of unique links extracted per document
DEFAULT_MAX_LINK_LENGTH = 2048  # Maximum length of an individual extracted link
DEFAULT_SUPPORTED_LINK_RELS = frozenset({"canonical"})

# Tags whose inner contents must not be parsed for links
IGNORED_BLOCK_TAGS = frozenset({"script", "style", "svg", "noscript"})

# Tags with subresources or forms that must NEVER be extracted as navigational links
SUBRESOURCE_AND_FORM_TAGS = frozenset(
    {
        "script",
        "style",
        "img",
        "video",
        "audio",
        "source",
        "track",
        "picture",
        "iframe",
        "frame",
        "frameset",
        "object",
        "embed",
        "applet",
        "form",
        "input",
        "button",
        "select",
        "textarea",
    }
)


class HTMLAnchorExtractor(HTMLParser):
    """Memory-bounded, streaming HTML parser extracting navigational links without JS execution."""

    def __init__(
        self,
        max_links: int = DEFAULT_MAX_LINKS,
        max_link_length: int = DEFAULT_MAX_LINK_LENGTH,
        supported_link_rels: Iterable[str] = DEFAULT_SUPPORTED_LINK_RELS,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.max_links = max_links
        self.max_link_length = max_link_length
        self.supported_link_rels = frozenset(r.lower() for r in supported_link_rels)

        self._links: list[str] = []
        self._seen: set[str] = set()
        self._ignored_depth = 0

    @property
    def links(self) -> list[str]:
        """Return the list of unique extracted links in document appearance order."""
        return list(self._links)

    def _record_link(self, raw_href: str | None) -> None:
        """Validate, bound, and record a candidate href attribute."""
        if raw_href is None:
            return

        stripped = raw_href.strip()
        if not stripped:
            return

        if len(stripped) > self.max_link_length:
            return

        if stripped not in self._seen and len(self._links) < self.max_links:
            self._seen.add(stripped)
            self._links.append(stripped)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()

        # Track entry into script/style/ignored blocks
        if tag_lower in IGNORED_BLOCK_TAGS:
            self._ignored_depth += 1
            return

        if self._ignored_depth > 0:
            return

        # Explicitly skip subresources and form controls
        if tag_lower in SUBRESOURCE_AND_FORM_TAGS:
            return

        if len(self._links) >= self.max_links:
            return

        # Extract first non-None occurrence of each attribute (deterministic duplicate handling)
        first_attrs: dict[str, str] = {}
        for k, v in attrs:
            if k is not None:
                attr_name = k.lower()
                if attr_name not in first_attrs and v is not None:
                    first_attrs[attr_name] = v

        if tag_lower in ("a", "area"):
            raw_href = first_attrs.get("href")
            self._record_link(raw_href)
        elif tag_lower == "link":
            rel_str = first_attrs.get("rel", "")
            rel_tokens = {token.lower() for token in rel_str.split()}
            if any(token in self.supported_link_rels for token in rel_tokens):
                raw_href = first_attrs.get("href")
                self._record_link(raw_href)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in IGNORED_BLOCK_TAGS and self._ignored_depth > 0:
            self._ignored_depth -= 1

    def handle_comment(self, data: str) -> None:
        """Ignore HTML comments entirely to avoid extracting commented-out links."""


def extract_links(
    html: str | bytes,
    max_html_chars: int = DEFAULT_MAX_HTML_CHARS,
    max_links: int = DEFAULT_MAX_LINKS,
    max_link_length: int = DEFAULT_MAX_LINK_LENGTH,
    supported_link_rels: Iterable[str] = DEFAULT_SUPPORTED_LINK_RELS,
) -> list[str]:
    """Extract unique navigational link references from HTML markup.

    Args:
        html: Raw HTML content as string or bytes.
        max_html_chars: Maximum characters to parse (bounds input size).
        max_links: Maximum unique links to extract.
        max_link_length: Maximum allowed length for any individual link.
        supported_link_rels: Link rel attributes permitted for extraction (e.g. 'canonical').

    Returns:
        List of unique extracted link references in order of appearance.
    """
    if not html:
        return []

    if isinstance(html, bytes):
        bounded_html = html[:max_html_chars].decode("utf-8", errors="replace")
    elif isinstance(html, str):
        bounded_html = html[:max_html_chars]
    else:
        return []

    extractor = HTMLAnchorExtractor(
        max_links=max_links,
        max_link_length=max_link_length,
        supported_link_rels=supported_link_rels,
    )

    try:
        extractor.feed(bounded_html)
        extractor.close()
    except Exception:
        # Gracefully handle parser failures on extremely malformed input
        pass

    return extractor.links
