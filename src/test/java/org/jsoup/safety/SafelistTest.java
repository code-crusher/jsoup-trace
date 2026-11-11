package org.jsoup.safety;

import org.jsoup.helper.ValidationException;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.parser.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SafelistTest {
    private static final String TEST_TAG = "testTag";
    private static final String TEST_ATTRIBUTE = "testAttribute";
    private static final String TEST_SCHEME = "valid-scheme";
    private static final String TEST_VALUE = TEST_SCHEME + "://testValue";

    @Test
    public void testCopyConstructor_noSideEffectOnTags() {
        Safelist safelist1 = Safelist.none().addTags(TEST_TAG);
        Safelist safelist2 = new Safelist(safelist1);
        safelist1.addTags("invalidTag");

        assertFalse(safelist2.isSafeTag("invalidTag"));
    }

    @Test
    public void testCopyConstructor_noSideEffectOnAttributes() {
        Safelist safelist1 = Safelist.none().addAttributes(TEST_TAG, TEST_ATTRIBUTE);
        Safelist safelist2 = new Safelist(safelist1);
        safelist1.addAttributes(TEST_TAG, "invalidAttribute");

        assertFalse(safelist2.isSafeAttribute(TEST_TAG, null, new Attribute("invalidAttribute", TEST_VALUE)));
    }

    @Test
    public void testCopyConstructor_noSideEffectOnEnforcedAttributes() {
        Safelist safelist1 = Safelist.none().addEnforcedAttribute(TEST_TAG, TEST_ATTRIBUTE, TEST_VALUE);
        Safelist safelist2 = new Safelist(safelist1);
        safelist1.addEnforcedAttribute(TEST_TAG, TEST_ATTRIBUTE, "invalidValue");

        for (Attribute enforcedAttribute : safelist2.getEnforcedAttributes(TEST_TAG)) {
            assertNotEquals("invalidValue", enforcedAttribute.getValue());
        }
    }

    @Test
    public void testCopyConstructor_noSideEffectOnProtocols() {
        final String invalidScheme = "invalid-scheme";
        Safelist safelist1 = Safelist.none()
                .addAttributes(TEST_TAG, TEST_ATTRIBUTE)
                .addProtocols(TEST_TAG, TEST_ATTRIBUTE, TEST_SCHEME);
        Safelist safelist2 = new Safelist(safelist1);
        safelist1.addProtocols(TEST_TAG, TEST_ATTRIBUTE, invalidScheme);

        Attributes attributes = new Attributes();
        Attribute invalidAttribute = new Attribute(TEST_ATTRIBUTE, invalidScheme + "://someValue");
        attributes.put(invalidAttribute);
        Element invalidElement = new Element(Tag.valueOf(TEST_TAG), "", attributes);

        assertFalse(safelist2.isSafeAttribute(TEST_TAG, invalidElement, invalidAttribute));
    }

    @Test
    void isSafeAttributeDoesNotModifyLiveAttribute() {
        Attributes attributes = new Attributes().put("href", "/foo");
        Element link = new Element(Tag.valueOf("a"), "https://example.com/", attributes);
        Attribute href = link.attributes().attribute("href");
        assertNotNull(href);

        assertTrue(Safelist.basic().isSafeAttribute("a", link, href));
        assertEquals("/foo", href.getValue());
        assertEquals("/foo", link.attr("href"));
    }

    @Test
    void enforcedAttributeMatchesInputKeyCaseInsensitively() {
        Attribute rel = new Attribute("REL", "nofollow");
        Attributes attributes = new Attributes().put(rel);
        Element link = new Element(Tag.valueOf("a"), "", attributes);

        assertTrue(Safelist.basic().isSafeAttribute("a", link, rel));
    }

    @Test
    void noscriptIsBlocked() {
        boolean threw = false;
        Safelist safelist = null;
        try {
            safelist = Safelist.none().addTags("NOSCRIPT");
        } catch (ValidationException validationException) {
            threw = true;
            assertTrue(validationException.getMessage().contains("unsupported"));
        }
        assertTrue(threw);
        assertNull(safelist);
    }

    @Test
    void namesUseAsciiCaseFolding() {
        Safelist safelist = Safelist.none()
            .addTags("P", "X-Ä")
            .addAttributes("P", "DATA-Ä");

        assertTrue(safelist.isSafeTag("p"));
        assertTrue(safelist.isSafeTag("x-Ä"));
        assertFalse(safelist.isSafeTag("x-ä"));
        assertTrue(safelist.isSafeAttribute("p", null, new Attribute("data-Ä", TEST_VALUE)));
        assertFalse(safelist.isSafeAttribute("p", null, new Attribute("data-ä", TEST_VALUE)));
    }

    // ---- Issue #2284: namespace-aware, Tag-based configuration ----

    @Test
    void tagsCanBeAddedByNameOrNamespace() {
        Tag svgCircle = new Tag("circle", Parser.NamespaceSvg);
        Tag htmlCircle = new Tag("circle", Parser.NamespaceHtml);
        Safelist safelist = Safelist.none().addTags(svgCircle);

        assertTrue(safelist.isSafeTag(svgCircle));
        assertFalse(safelist.isSafeTag(htmlCircle));
        assertTrue(safelist.isSafeTag("circle")); // the name-only check is namespace agnostic
        assertTrue(safelist.isSafeTag("circle", Parser.NamespaceSvg));
        assertFalse(safelist.isSafeTag("circle", Parser.NamespaceHtml));

        // a name-only tag is allowed in any namespace
        Safelist byName = Safelist.none().addTags("circle");
        assertTrue(byName.isSafeTag(svgCircle));
        assertTrue(byName.isSafeTag(htmlCircle));
    }

    @Test
    void attributesAndProtocolsCanBeNamespaced() {
        Tag svgUse = new Tag("use", Parser.NamespaceSvg);
        Tag htmlUse = new Tag("use", Parser.NamespaceHtml);
        Safelist safelist = Safelist.none()
            .addTags(svgUse, htmlUse)
            .addAttributes(svgUse, "href")
            .addProtocols(svgUse, "href", "#")
            .addEnforcedAttribute(svgUse, "role", "img");

        Element svgEl = new Element(svgUse, "");
        Element htmlEl = new Element(htmlUse, "");
        assertTrue(safelist.isSafeAttribute(svgUse, svgEl, new Attribute("href", "#foo")));
        assertFalse(safelist.isSafeAttribute(svgUse, svgEl, new Attribute("href", "https://example.com/")));
        assertFalse(safelist.isSafeAttribute(htmlUse, htmlEl, new Attribute("href", "#foo")));
        assertEquals("img", safelist.getEnforcedAttributes(svgUse).get("role"));
        assertEquals("", safelist.getEnforcedAttributes(htmlUse).get("role"));

        safelist.removeAttributes(svgUse, "href");
        assertFalse(safelist.isSafeAttribute(svgUse, null, new Attribute("href", "#foo")));
    }

    @Test
    void html5ListsAreNamespaceAware() {
        Safelist relaxed5 = Safelist.relaxed5();
        assertTrue(relaxed5.isSafeTag(new Tag("svg", Parser.NamespaceSvg)));
        assertTrue(relaxed5.isSafeTag(new Tag("math", Parser.NamespaceMathml)));
        assertFalse(relaxed5.isSafeTag(new Tag("script", Parser.NamespaceSvg)));
        assertFalse(relaxed5.isSafeTag(new Tag("foreignObject", Parser.NamespaceSvg)));
        // html p is allowed; name-only configured tags (like p) are allowed in any namespace, for back-compat
        assertTrue(relaxed5.isSafeTag(new Tag("p", Parser.NamespaceHtml)));
        assertTrue(relaxed5.isSafeTag(new Tag("p", Parser.NamespaceSvg)));
        // but a tag configured only in a namespace is not allowed in another
        assertFalse(Safelist.none().addTags(new Tag("p", Parser.NamespaceSvg)).isSafeTag(new Tag("p", Parser.NamespaceHtml)));
    }

    @Test
    void legacyListsAreUnchanged() {
        // the original lists must remain stable; new elements only go into the *5 lists
        assertFalse(Safelist.relaxed().isSafeTag("article"));
        assertFalse(Safelist.relaxed().isSafeTag("mark"));
        assertFalse(Safelist.relaxed().isSafeTag("svg"));
        assertTrue(Safelist.relaxed5().isSafeTag("article"));
        assertTrue(Safelist.relaxed5().isSafeTag("mark"));
        assertTrue(Safelist.relaxed5().isSafeTag("svg"));
    }

    @Test
    void wildcardAttributes() {
        Safelist safelist = Safelist.none().addTags("p").addAttributes(":all", "data-*", "aria-*");

        assertTrue(safelist.isSafeAttribute("p", null, new Attribute("data-foo", "1")));
        assertTrue(safelist.isSafeAttribute("p", null, new Attribute("aria-label", "1")));
        assertFalse(safelist.isSafeAttribute("p", null, new Attribute("class", "1")));
        assertFalse(safelist.isSafeAttribute("p", null, new Attribute("data", "1")));

        safelist.removeAttributes(":all", "data-*");
        assertFalse(safelist.isSafeAttribute("p", null, new Attribute("data-foo", "1")));
    }

    @Test
    void dataImageProtocol() {
        Safelist safelist = Safelist.none().addTags("img")
            .addAttributes("img", "src")
            .addProtocols("img", "src", "data:image");

        assertTrue(safelist.isSafeAttribute("img", null, new Attribute("src", "data:image/png;base64,iVBORw0KGgo=")));
        assertFalse(safelist.isSafeAttribute("img", null, new Attribute("src", "data:text/html;base64,PHNjcmlwdD4=")));
        assertFalse(safelist.isSafeAttribute("img", null, new Attribute("src", "data:image/svg+xml,<svg/>")));
        assertFalse(safelist.isSafeAttribute("img", null, new Attribute("src", "data:image/png;base64,abc def")));
    }

    @Test
    void rejectedElementHandlingDefaultsToUnwrap() {
        Safelist safelist = Safelist.relaxed();
        assertEquals(Safelist.RejectedElementHandling.Unwrap, safelist.rejectedElementHandling("form"));
        assertEquals(Safelist.RejectedElementHandling.Unwrap, safelist.rejectedElementHandling(new Tag("form")));

        safelist.rejectedElementHandling("form", Safelist.RejectedElementHandling.DiscardSubtree);
        assertEquals(Safelist.RejectedElementHandling.DiscardSubtree, safelist.rejectedElementHandling("form"));
        assertEquals(Safelist.RejectedElementHandling.Unwrap, safelist.rejectedElementHandling("table"));

        safelist.rejectedElementHandling(Safelist.RejectedElementHandling.DiscardSubtree);
        assertEquals(Safelist.RejectedElementHandling.DiscardSubtree, safelist.rejectedElementHandling("table"));

        // copy constructor copies the handling
        Safelist copy = new Safelist(safelist);
        assertEquals(Safelist.RejectedElementHandling.DiscardSubtree, copy.rejectedElementHandling("table"));
    }

    @Test
    void removingTagsRemovesNamespacedConfig() {
        Tag svgCircle = new Tag("circle", Parser.NamespaceSvg);
        Safelist safelist = Safelist.none()
            .addTags(svgCircle)
            .addAttributes(svgCircle, "cx")
            .addEnforcedAttribute(svgCircle, "fill", "red")
            .addProtocols(svgCircle, "cx", "http");

        assertTrue(safelist.isSafeTag(svgCircle));
        safelist.removeTags("circle");
        assertFalse(safelist.isSafeTag(svgCircle));
        assertEquals("", safelist.getEnforcedAttributes(svgCircle).get("fill"));
    }
}
