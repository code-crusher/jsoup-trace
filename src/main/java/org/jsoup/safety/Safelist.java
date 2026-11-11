package org.jsoup.safety;

/*
    Thank you to Ryan Grove (wonko.com) for the Ruby HTML cleaner http://github.com/rgrove/sanitize/, which inspired
    this safe-list configuration, and the initial defaults.
 */

import org.jsoup.helper.Validate;
import org.jsoup.internal.Normalizer;
import org.jsoup.internal.StringUtil;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.jsoup.internal.Normalizer.asciiLowerCase;
import static org.jsoup.internal.Normalizer.lowerCase;
import static org.jsoup.parser.Parser.NamespaceMathml;
import static org.jsoup.parser.Parser.NamespaceSvg;


/**
 Safelists define what HTML (elements and attributes) to allow through a {@link Cleaner}. Everything else is removed.
 <p>
 Start with one of the defaults:
 </p>
 <ul>
 <li>{@link #none}
 <li>{@link #simpleText}
 <li>{@link #basic}
 <li>{@link #basicWithImages}
 <li>{@link #relaxed}
 </ul>
 <p>
 Or, for the evolving, namespace-aware HTML5 lists (which may add or remove elements in future releases):
 </p>
 <ul>
 <li>{@link #simpleText5}
 <li>{@link #basic5}
 <li>{@link #basicWithImages5}
 <li>{@link #relaxed5}
 </ul>
 <p>
 If you need to allow more through (please be careful!), tweak a base safelist with:
 </p>
 <ul>
 <li>{@link #addTags(String... tagNames)}
 <li>{@link #addTags(Tag... tags)}
 <li>{@link #addAttributes(String tagName, String... attributes)}
 <li>{@link #addAttributes(Tag tag, String... attributes)}
 <li>{@link #addEnforcedAttribute(String tagName, String attribute, String value)}
 <li>{@link #addEnforcedAttribute(Tag tag, String attribute, String value)}
 <li>{@link #addProtocols(String tagName, String attribute, String... protocols)}
 <li>{@link #addProtocols(Tag tag, String attribute, String... protocols)}
 </ul>
 <p>
 You can remove any setting from an existing safelist with:
 </p>
 <ul>
 <li>{@link #removeTags(String... tagNames)}
 <li>{@link #removeAttributes(String tagName, String... attributes)}
 <li>{@link #removeEnforcedAttribute(String tagName, String attribute)}
 <li>{@link #removeProtocols(String tagName, String attribute, String... removeProtocols)}
 </ul>
 <p>
 Attribute names may be configured as wildcards, by ending them with an asterisk. For example,
 {@code addAttributes(":all", "data-*", "aria-*")} allows all {@code data-} and {@code aria-} attributes on all
 elements.
 </p>
 <p>
 To allow base64 encoded image data URIs, add the {@code data:image} protocol (e.g.
 {@code addProtocols("img", "src", "data:image")}). Only {@code data:image/...;base64,...} values are then permitted.
 </p>
 <p>
 The {@link Cleaner} and these safelists assume that you want to clean a <code>body</code> fragment of HTML (to add user
 supplied HTML into a templated page), and not to clean a full HTML document. If the latter is the case, you could wrap
 the templated document HTML around the cleaned body HTML, or add the {@code html}, {@code head}, and {@code body} tags
 to the safelist (which will make the {@link Cleaner} clean the full document).
 </p>
 <p>
 Safelists are mutable. A {@link Cleaner} uses the supplied safelist directly, so later changes affect later cleaning
 calls. If you want to share a safelist across threads, finish configuring it first and do not mutate it while it is in
 use. To build a variant from an existing configuration, use {@link #Safelist(Safelist)} to make a copy.
 </p>
 <p>
 If you are going to extend a safelist, please be very careful. Make sure you understand what attributes may lead to
 XSS attack vectors. URL attributes are particularly vulnerable and require careful validation. See
 the <a href="https://owasp.org/www-community/xss-filter-evasion-cheatsheet">XSS Filter Evasion Cheat Sheet</a> for some
 XSS attack examples (that jsoup will safeguard against with the default Cleaner and Safelist configuration).
 </p>
 */
public class Safelist {
    private static final String All = ":all";
    private final Set<TagKey> tags; // tags allowed. keyed by (optional) namespace and normal name
    private final Map<TagKey, Set<AttributeKey>> attributes; // tag -> attribute[]. allowed attributes [href] for a tag.
    private final Map<TagKey, Map<AttributeKey, AttributeValue>> enforcedAttributes; // always set these attribute values
    private final Map<TagKey, Map<AttributeKey, Set<Protocol>>> protocols; // allowed URL protocols for attributes
    private final Map<TagKey, RejectedElementHandling> rejectedHandling; // per-element rejected handling
    private RejectedElementHandling defaultRejectedHandling = RejectedElementHandling.Unwrap;
    private boolean preserveRelativeLinks; // option to preserve relative links

    /**
     How an element that is not allowed by the safelist is handled by a {@link Cleaner}.
     @since 1.24.2
     */
    public enum RejectedElementHandling {
        /** Remove the rejected element, but keep its (individually validated) descendants. This is the default, and
         matches the behavior of earlier versions. */
        Unwrap,
        /** Remove the rejected element and its entire subtree, without keeping any descendants. */
        DiscardSubtree
    }

    /**
     This safelist allows only text nodes: any HTML Element or any Node other than a TextNode will be removed.
     <p>
     Note that the output of {@link org.jsoup.Jsoup#clean(String, Safelist)} is still <b>HTML</b> even when using
     this Safelist, and so any HTML entities in the output will be appropriately escaped. If you want plain text, not
     HTML, you should use a text method such as {@link Element#text()} instead, after cleaning the document.
     </p>
     <p>Example:</p>
     <pre>{@code
     String sourceBodyHtml = "<p>5 is &lt; 6.</p>";
     String html = Jsoup.clean(sourceBodyHtml, Safelist.none());

     Cleaner cleaner = new Cleaner(Safelist.none());
     String text = cleaner.clean(Jsoup.parse(sourceBodyHtml)).text();

     // html is: 5 is &lt; 6.
     // text is: 5 is < 6.
     }</pre>

     @return safelist
     */
    public static Safelist none() {
        return new Safelist();
    }

    /**
     This safelist allows only simple text formatting: <code>b, em, i, strong, u</code>. All other HTML (tags and
     attributes) will be removed.

     @return safelist
     */
    public static Safelist simpleText() {
        return new Safelist()
                .addTags("b", "em", "i", "strong", "u")
                ;
    }

    /**
     <p>
     This safelist allows a fuller range of text nodes: <code>a, b, blockquote, br, cite, code, dd, dl, dt, em, i, li,
     ol, p, pre, q, small, span, strike, strong, sub, sup, u, ul</code>, and appropriate attributes.
     </p>
     <p>
     Links (<code>a</code> elements) can point to <code>http, https, ftp, mailto</code>, and have an enforced
     <code>rel=nofollow</code> attribute if they link offsite (as indicated by the specified base URI).
     </p>
     <p>
     Does not allow images.
     </p>

     @return safelist
     */
    public static Safelist basic() {
        return new Safelist()
                .addTags(
                        "a", "b", "blockquote", "br", "cite", "code", "dd", "dl", "dt", "em",
                        "i", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong", "sub",
                        "sup", "u", "ul")

                .addAttributes("a", "href")
                .addAttributes("blockquote", "cite")
                .addAttributes("q", "cite")

                .addProtocols("a", "href", "ftp", "http", "https", "mailto")
                .addProtocols("blockquote", "cite", "http", "https")
                .addProtocols("cite", "cite", "http", "https")

                .addEnforcedAttribute("a", "rel", "nofollow") // has special handling for external links, in Cleaner
                ;

    }

    /**
     This safelist allows the same text tags as {@link #basic}, and also allows <code>img</code> tags, with appropriate
     attributes, with <code>src</code> pointing to <code>http</code> or <code>https</code>.

     @return safelist
     */
    public static Safelist basicWithImages() {
        return basic()
                .addTags("img")
                .addAttributes("img", "align", "alt", "height", "src", "title", "width")
                .addProtocols("img", "src", "http", "https")
                ;
    }

    /**
     This safelist allows a full range of text and structural body HTML: <code>a, b, blockquote, br, caption, cite,
     code, col, colgroup, dd, div, dl, dt, em, h1, h2, h3, h4, h5, h6, i, img, li, ol, p, pre, q, small, span, strike, strong, sub,
     sup, table, tbody, td, tfoot, th, thead, tr, u, ul</code>
     <p>
     Links do not have an enforced <code>rel=nofollow</code> attribute, but you can add that if desired.
     </p>

     @return safelist
     */
    public static Safelist relaxed() {
        return new Safelist()
                .addTags(
                        "a", "b", "blockquote", "br", "caption", "cite", "code", "col",
                        "colgroup", "dd", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6",
                        "i", "img", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong",
                        "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u",
                        "ul")

                .addAttributes("a", "href", "title")
                .addAttributes("blockquote", "cite")
                .addAttributes("col", "span", "width")
                .addAttributes("colgroup", "span", "width")
                .addAttributes("img", "align", "alt", "height", "src", "title", "width")
                .addAttributes("ol", "start", "type")
                .addAttributes("q", "cite")
                .addAttributes("table", "summary", "width")
                .addAttributes("td", "abbr", "axis", "colspan", "rowspan", "width")
                .addAttributes(
                        "th", "abbr", "axis", "colspan", "rowspan", "scope",
                        "width")
                .addAttributes("ul", "type")

                .addProtocols("a", "href", "ftp", "http", "https", "mailto")
                .addProtocols("blockquote", "cite", "http", "https")
                .addProtocols("cite", "cite", "http", "https")
                .addProtocols("img", "src", "http", "https")
                .addProtocols("q", "cite", "http", "https")
                ;
    }

    /**
     This safelist allows simple HTML5 text formatting: <code>b, em, i, mark, s, small, strong, sub, sup, u</code>.
     <p>This is the HTML5-oriented counterpart of {@link #simpleText()}. Unlike the original lists, the {@code 5} lists
     may gain or lose elements in future releases, as HTML5 evolves.</p>

     @return safelist
     @since 1.24.2
     */
    public static Safelist simpleText5() {
        return new Safelist()
            .addTags("b", "em", "i", "mark", "s", "small", "strong", "sub", "sup", "u")
            ;
    }

    /**
     This safelist allows a fuller range of HTML5 text and sectioning elements, and appropriate attributes.
     <p>Links ({@code a} elements) can point to <code>http, https, ftp, mailto</code>, and have an enforced
     <code>rel=nofollow</code> attribute if they link offsite. Does not allow images.</p>
     <p>This is the HTML5-oriented counterpart of {@link #basic()}. Unlike the original lists, the {@code 5} lists may
     gain or lose elements in future releases, as HTML5 evolves.</p>

     @return safelist
     @since 1.24.2
     */
    public static Safelist basic5() {
        return new Safelist()
            .addTags(
                "a", "abbr", "b", "bdi", "bdo", "blockquote", "br", "cite", "code", "data", "dd", "del", "dfn",
                "div", "dl", "dt", "em", "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i",
                "ins", "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "samp", "small", "span", "strong", "sub",
                "sup", "time", "u", "ul", "var", "wbr")

            .addAttributes("a", "href", "title")
            .addAttributes("blockquote", "cite")
            .addAttributes("data", "value")
            .addAttributes("del", "cite", "datetime")
            .addAttributes("ins", "cite", "datetime")
            .addAttributes("ol", "reversed", "start", "type")
            .addAttributes("q", "cite")
            .addAttributes("time", "datetime")

            .addProtocols("a", "href", "ftp", "http", "https", "mailto")
            .addProtocols("blockquote", "cite", "http", "https")
            .addProtocols("cite", "cite", "http", "https")
            .addProtocols("del", "cite", "http", "https")
            .addProtocols("ins", "cite", "http", "https")
            .addProtocols("q", "cite", "http", "https")

            .addEnforcedAttribute("a", "rel", "nofollow")
            ;
    }

    /**
     This safelist allows the same HTML5 tags as {@link #basic5}, and also allows <code>img</code> tags, with appropriate
     attributes, with <code>src</code> pointing to <code>http</code> or <code>https</code>.
     <p>This is the HTML5-oriented counterpart of {@link #basicWithImages()}. Unlike the original lists, the {@code 5}
     lists may gain or lose elements in future releases, as HTML5 evolves.</p>

     @return safelist
     @since 1.24.2
     */
    public static Safelist basicWithImages5() {
        return basic5()
            .addTags("img")
            .addAttributes("img", "alt", "height", "src", "srcset", "title", "width")
            .addProtocols("img", "src", "http", "https")
            ;
    }

    /**
     This safelist allows a full range of HTML5 text and structural body HTML, including a conservative subset of the
     SVG and MathML namespaces, and wildcard {@code data-*} and {@code aria-*} attributes.
     <p>
     This is the HTML5-oriented counterpart of {@link #relaxed()}. Unlike the original lists, the {@code 5} lists may
     gain or lose elements in future releases, as HTML5 evolves.
     </p>
     <p>
     Namespaced elements are configured with {@link Tag} objects, so (for example) an SVG {@code script} element is
     distinct from an HTML {@code script} element. The SVG and MathML lists here are a conservative safe subset; notably,
     SVG {@code script}, {@code foreignObject}, and animation elements are not allowed.
     </p>

     @return safelist
     @since 1.24.2
     */
    public static Safelist relaxed5() {
        Tag svg = new Tag("svg", NamespaceSvg);
        Tag math = new Tag("math", NamespaceMathml);
        return relaxed()
            .addTags(
                "abbr", "article", "aside", "bdi", "bdo", "data", "del", "details", "dfn", "dialog",
                "figcaption", "figure", "footer", "header", "hgroup", "hr", "ins", "kbd", "main", "mark",
                "nav", "s", "samp", "section", "summary", "time", "var", "wbr")

            .addAttributes("data", "value")
            .addAttributes("del", "cite", "datetime")
            .addAttributes("details", "open")
            .addAttributes("ins", "cite", "datetime")
            .addAttributes("ol", "reversed")
            .addAttributes("time", "datetime")

            .addProtocols("del", "cite", "http", "https")
            .addProtocols("ins", "cite", "http", "https")

            // HTML5 allows data-* and aria-* attributes on all elements; these are non-URL, and are safe
            .addAttributes(All, "data-*", "aria-*")

            .addTags(
                svg,
                new Tag("circle", NamespaceSvg), new Tag("ellipse", NamespaceSvg), new Tag("g", NamespaceSvg),
                new Tag("line", NamespaceSvg), new Tag("path", NamespaceSvg), new Tag("polygon", NamespaceSvg),
                new Tag("polyline", NamespaceSvg), new Tag("rect", NamespaceSvg), new Tag("text", NamespaceSvg),
                new Tag("tspan", NamespaceSvg), new Tag("defs", NamespaceSvg), new Tag("desc", NamespaceSvg),
                new Tag("title", NamespaceSvg), new Tag("symbol", NamespaceSvg), new Tag("use", NamespaceSvg),
                new Tag("marker", NamespaceSvg), new Tag("linearGradient", NamespaceSvg),
                new Tag("radialGradient", NamespaceSvg), new Tag("stop", NamespaceSvg),
                new Tag("clipPath", NamespaceSvg), new Tag("mask", NamespaceSvg), new Tag("pattern", NamespaceSvg),
                new Tag("image", NamespaceSvg))

            .addAttributes(svg, "viewBox", "width", "height", "preserveAspectRatio", "version", "xmlns", "role")
            .addAttributes(new Tag("circle", NamespaceSvg), "cx", "cy", "r", "fill", "stroke", "stroke-width")
            .addAttributes(new Tag("ellipse", NamespaceSvg), "cx", "cy", "rx", "ry", "fill", "stroke", "stroke-width")
            .addAttributes(new Tag("g", NamespaceSvg), "fill", "stroke", "stroke-width", "transform")
            .addAttributes(new Tag("line", NamespaceSvg), "x1", "y1", "x2", "y2", "stroke", "stroke-width")
            .addAttributes(new Tag("path", NamespaceSvg), "d", "fill", "stroke", "stroke-width", "fill-rule")
            .addAttributes(new Tag("polygon", NamespaceSvg), "points", "fill", "stroke", "stroke-width")
            .addAttributes(new Tag("polyline", NamespaceSvg), "points", "fill", "stroke", "stroke-width")
            .addAttributes(new Tag("rect", NamespaceSvg), "x", "y", "width", "height", "rx", "ry", "fill", "stroke",
                "stroke-width")
            .addAttributes(new Tag("text", NamespaceSvg), "x", "y", "dx", "dy", "fill", "font-size", "text-anchor")
            .addAttributes(new Tag("tspan", NamespaceSvg), "x", "y", "dx", "dy")
            .addAttributes(new Tag("use", NamespaceSvg), "href", "x", "y", "width", "height")
            .addAttributes(new Tag("marker", NamespaceSvg), "markerWidth", "markerHeight", "refX", "refY",
                "orient", "markerUnits")
            .addAttributes(new Tag("linearGradient", NamespaceSvg), "x1", "y1", "x2", "y2",
                "gradientUnits", "gradientTransform")
            .addAttributes(new Tag("radialGradient", NamespaceSvg), "cx", "cy", "r", "fx", "fy",
                "gradientUnits", "gradientTransform")
            .addAttributes(new Tag("stop", NamespaceSvg), "offset", "stop-color", "stop-opacity")
            .addAttributes(new Tag("clipPath", NamespaceSvg), "clipPathUnits")
            .addAttributes(new Tag("mask", NamespaceSvg), "maskUnits", "x", "y", "width", "height")
            .addAttributes(new Tag("pattern", NamespaceSvg), "patternUnits", "width", "height", "x", "y")
            .addAttributes(new Tag("image", NamespaceSvg), "href", "x", "y", "width", "height",
                "preserveAspectRatio")
            .addProtocols(new Tag("use", NamespaceSvg), "href", "#")
            .addProtocols(new Tag("image", NamespaceSvg), "href", "http", "https")

            .addTags(
                math,
                new Tag("mi", NamespaceMathml), new Tag("mn", NamespaceMathml), new Tag("mo", NamespaceMathml),
                new Tag("ms", NamespaceMathml), new Tag("mtext", NamespaceMathml), new Tag("mrow", NamespaceMathml),
                new Tag("mfrac", NamespaceMathml), new Tag("msqrt", NamespaceMathml), new Tag("mroot", NamespaceMathml),
                new Tag("mstyle", NamespaceMathml), new Tag("merror", NamespaceMathml),
                new Tag("mtable", NamespaceMathml), new Tag("mtr", NamespaceMathml), new Tag("mtd", NamespaceMathml),
                new Tag("msub", NamespaceMathml), new Tag("msup", NamespaceMathml),
                new Tag("msubsup", NamespaceMathml), new Tag("munder", NamespaceMathml),
                new Tag("mover", NamespaceMathml), new Tag("munderover", NamespaceMathml))

            .addAttributes(math, "display", "xmlns")
            .addAttributes(new Tag("mstyle", NamespaceMathml), "displaystyle", "scriptlevel")
            .addAttributes(new Tag("mtable", NamespaceMathml), "columnalign", "rowspacing", "columnspacing")
            .addAttributes(new Tag("mtd", NamespaceMathml), "columnalign", "rowspan", "columnspan")
            .addAttributes(new Tag("mo", NamespaceMathml), "fence", "separator", "stretchy", "lspace", "rspace")
            ;
    }

    /**
     Create a new, empty safelist. Generally it will be better to start with a default prepared safelist instead.

     @see #basic()
     @see #basicWithImages()
     @see #simpleText()
     @see #relaxed()
     @see #relaxed5()
     */
    public Safelist() {
        tags = new HashSet<>();
        attributes = new HashMap<>();
        enforcedAttributes = new HashMap<>();
        protocols = new HashMap<>();
        rejectedHandling = new HashMap<>();
        preserveRelativeLinks = false;
    }

    /**
     Deep copy an existing Safelist to a new Safelist.
     @param copy the Safelist to copy
     */
    public Safelist(Safelist copy) {
        this();
        tags.addAll(copy.tags);
        for (Map.Entry<TagKey, Set<AttributeKey>> copyTagAttributes : copy.attributes.entrySet()) {
            attributes.put(copyTagAttributes.getKey(), new HashSet<>(copyTagAttributes.getValue()));
        }
        for (Map.Entry<TagKey, Map<AttributeKey, AttributeValue>> enforcedEntry : copy.enforcedAttributes.entrySet()) {
            enforcedAttributes.put(enforcedEntry.getKey(), new HashMap<>(enforcedEntry.getValue()));
        }
        for (Map.Entry<TagKey, Map<AttributeKey, Set<Protocol>>> protocolsEntry : copy.protocols.entrySet()) {
            Map<AttributeKey, Set<Protocol>> attributeProtocolsCopy = new HashMap<>();
            for (Map.Entry<AttributeKey, Set<Protocol>> attributeProtocols : protocolsEntry.getValue().entrySet()) {
                attributeProtocolsCopy.put(attributeProtocols.getKey(), new HashSet<>(attributeProtocols.getValue()));
            }
            protocols.put(protocolsEntry.getKey(), attributeProtocolsCopy);
        }
        rejectedHandling.putAll(copy.rejectedHandling);
        defaultRejectedHandling = copy.defaultRejectedHandling;
        preserveRelativeLinks = copy.preserveRelativeLinks;
    }

    /**
     Add a list of allowed elements to a safelist. (If a tag is not allowed, it will be removed from the HTML.)
     <p>The tags are allowed in any namespace. To allow a tag only in a specific namespace (such as SVG or MathML),
     use {@link #addTags(Tag...)}.</p>

     @param tags tag names to allow
     @return this (for chaining)
     */
    public Safelist addTags(String... tags) {
        Validate.notNull(tags);

        for (String tagName : tags) {
            validateTagName(tagName);
            this.tags.add(TagKey.valueOf(tagName));
        }
        return this;
    }

    /**
     Add a list of allowed elements to a safelist, using {@link Tag} objects which carry both the element name and its
     namespace. (If a tag is not allowed, it will be removed from the HTML.)
     <p>For example, to allow SVG elements:</p>
     <pre>{@code
     Safelist safelist = Safelist.relaxed5()
         .addTags(new Tag("svg", Parser.NamespaceSvg))
         .addAttributes(new Tag("svg", Parser.NamespaceSvg), "viewBox");
     }</pre>

     @param tags tags to allow
     @return this (for chaining)
     @since 1.24.2
     */
    public Safelist addTags(Tag... tags) {
        Validate.notNull(tags);

        for (Tag tag : tags) {
            Validate.notNull(tag);
            validateTagName(tag.getName());
            this.tags.add(TagKey.valueOf(tag));
        }
        return this;
    }

    private static void validateTagName(String tagName) {
        Validate.notEmpty(tagName);
        Validate.isFalse(Normalizer.equalsIgnoreAsciiCase(tagName, "noscript"),
            "noscript is unsupported in Safelists, due to incompatibilities between parsers with and without script-mode enabled");
    }

    /**
     Remove a list of allowed elements from a safelist. (If a tag is not allowed, it will be removed from the HTML.)
     <p>Removes the tag from all namespaces in which it was allowed.</p>

     @param tags tag names to disallow
     @return this (for chaining)
     */
    public Safelist removeTags(String... tags) {
        Validate.notNull(tags);

        for (String tag : tags) {
            Validate.notEmpty(tag);
            String normalName = asciiLowerCase(tag);
            if (removeTagKeys(normalName)) // Only look in sub-maps if tag was allowed
                removeTagConfig(normalName);
        }
        return this;
    }

    /** Removes all tag keys with the given normal name (any namespace), returning true if any were removed. */
    private boolean removeTagKeys(String normalName) {
        boolean removed = false;
        Iterator<TagKey> it = tags.iterator();
        while (it.hasNext()) {
            if (it.next().normalName.equals(normalName)) {
                it.remove();
                removed = true;
            }
        }
        return removed;
    }

    /** Removes the attribute, enforced attribute, protocol, and handling config for a name, across namespaces. */
    private void removeTagConfig(String normalName) {
        removeMatching(attributes, normalName);
        removeMatching(enforcedAttributes, normalName);
        removeMatching(protocols, normalName);
        removeMatching(rejectedHandling, normalName);
    }

    private static <V> void removeMatching(Map<TagKey, V> map, String normalName) {
        Iterator<TagKey> it = map.keySet().iterator();
        while (it.hasNext()) {
            if (it.next().normalName.equals(normalName)) it.remove();
        }
    }

    /**
     Add a list of allowed attributes to a tag. (If an attribute is not allowed on an element, it will be removed.)
     <p>
     E.g.: <code>addAttributes("a", "href", "class")</code> allows <code>href</code> and <code>class</code> attributes
     on <code>a</code> tags.
     </p>
     <p>
     To make an attribute valid for <b>all tags</b>, use the pseudo tag <code>:all</code>, e.g.
     <code>addAttributes(":all", "class")</code>.
     </p>
     <p>
     Attribute names may be wildcards, by ending them with an asterisk. E.g. <code>addAttributes(":all", "data-*")</code>
     allows any attribute starting with <code>data-</code>.
     </p>

     @param tag  The tag the attributes are for. The tag will be added to the allowed tag list if necessary.
     @param attributes List of valid attributes for the tag
     @return this (for chaining)
     */
    public Safelist addAttributes(String tag, String... attributes) {
        Validate.notEmpty(tag);
        Validate.notNull(attributes);
        Validate.isTrue(attributes.length > 0, "No attribute names supplied.");

        addTags(tag);
        return addAttributes(TagKey.valueOf(tag), attributes);
    }

    /**
     Add a list of allowed attributes to a tag, using a {@link Tag} to specify the tag's namespace.
     <p>Attribute names may be wildcards, by ending them with an asterisk.</p>

     @param tag the tag the attributes are for; the tag will be added to the allowed tag list if necessary
     @param attributes list of valid attributes for the tag
     @return this (for chaining)
     @since 1.24.2
     */
    public Safelist addAttributes(Tag tag, String... attributes) {
        Validate.notNull(tag);
        Validate.notNull(attributes);
        Validate.isTrue(attributes.length > 0, "No attribute names supplied.");

        addTags(tag);
        return addAttributes(TagKey.valueOf(tag), attributes);
    }

    private Safelist addAttributes(TagKey tagKey, String... attributes) {
        Set<AttributeKey> attributeSet = new HashSet<>();
        for (String key : attributes) {
            Validate.notEmpty(key);
            attributeSet.add(AttributeKey.valueOf(key));
        }
        Set<AttributeKey> currentSet = this.attributes.computeIfAbsent(tagKey, k -> new HashSet<>());
        currentSet.addAll(attributeSet);
        return this;
    }

    /**
     Remove a list of allowed attributes from a tag. (If an attribute is not allowed on an element, it will be removed.)
     <p>
     E.g.: <code>removeAttributes("a", "href", "class")</code> disallows <code>href</code> and <code>class</code>
     attributes on <code>a</code> tags.
     </p>
     <p>
     To make an attribute invalid for <b>all tags</b>, use the pseudo tag <code>:all</code>, e.g.
     <code>removeAttributes(":all", "class")</code>.
     </p>

     @param tag  The tag the attributes are for.
     @param attributes List of invalid attributes for the tag
     @return this (for chaining)
     */
    public Safelist removeAttributes(String tag, String... attributes) {
        Validate.notEmpty(tag);
        Validate.notNull(attributes);
        Validate.isTrue(attributes.length > 0, "No attribute names supplied.");

        Set<AttributeKey> attributeSet = attributeKeys(attributes);
        if (tag.equals(All)) { // Attribute needs to be removed from all individually set tags
            Iterator<Map.Entry<TagKey, Set<AttributeKey>>> it = this.attributes.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<TagKey, Set<AttributeKey>> entry = it.next();
                Set<AttributeKey> currentSet = entry.getValue();
                currentSet.removeAll(attributeSet);
                if (currentSet.isEmpty()) // Remove tag from attribute map if no attributes are allowed for tag
                    it.remove();
            }
        } else {
            removeAttributesForName(asciiLowerCase(tag), attributeSet);
        }
        return this;
    }

    /**
     Remove a list of allowed attributes from a namespaced tag.

     @param tag the tag the attributes are for
     @param attributes list of invalid attributes for the tag
     @return this, for chaining
     @since 1.24.2
     */
    public Safelist removeAttributes(Tag tag, String... attributes) {
        Validate.notNull(tag);
        Validate.notNull(attributes);
        Validate.isTrue(attributes.length > 0, "No attribute names supplied.");

        Set<AttributeKey> attributeSet = attributeKeys(attributes);
        TagKey tagKey = TagKey.valueOf(tag);
        if (tags.contains(tagKey) && this.attributes.containsKey(tagKey)) {
            Set<AttributeKey> currentSet = this.attributes.get(tagKey);
            currentSet.removeAll(attributeSet);
            if (currentSet.isEmpty())
                this.attributes.remove(tagKey);
        }
        return this;
    }

    private static Set<AttributeKey> attributeKeys(String... attributes) {
        Set<AttributeKey> attributeSet = new HashSet<>();
        for (String key : attributes) {
            Validate.notEmpty(key);
            attributeSet.add(AttributeKey.valueOf(key));
        }
        return attributeSet;
    }

    private void removeAttributesForName(String normalName, Set<AttributeKey> attributeSet) {
        if (!isTagAllowedByName(normalName)) return; // Only look in sub-maps if tag was allowed
        Iterator<Map.Entry<TagKey, Set<AttributeKey>>> it = attributes.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<TagKey, Set<AttributeKey>> entry = it.next();
            if (!entry.getKey().normalName.equals(normalName)) continue;
            Set<AttributeKey> currentSet = entry.getValue();
            currentSet.removeAll(attributeSet);
            if (currentSet.isEmpty())
                it.remove();
        }
    }

    private boolean isTagAllowedByName(String normalName) {
        for (TagKey key : tags) {
            if (key.normalName.equals(normalName)) return true;
        }
        return false;
    }

    /**
     Add an enforced attribute to a tag. An enforced attribute will always be added to the element. If the element
     already has the attribute set, it will be overridden with this value.
     <p>
     E.g.: <code>addEnforcedAttribute("a", "rel", "nofollow")</code> will make all <code>a</code> tags output as
     <code>&lt;a href="..." rel="nofollow"&gt;</code>
     </p>

     @param tag   The tag the enforced attribute is for. The tag will be added to the allowed tag list if necessary.
     @param attribute   The attribute name
     @param value The enforced attribute value
     @return this (for chaining)
     */
    public Safelist addEnforcedAttribute(String tag, String attribute, String value) {
        Validate.notEmpty(tag);
        Validate.notEmpty(attribute);
        Validate.notEmpty(value);

        TagKey tagKey = TagKey.valueOf(tag);
        tags.add(tagKey);
        return addEnforcedAttribute(tagKey, attribute, value);
    }

    /**
     Add an enforced attribute to a namespaced tag. An enforced attribute will always be added to the element. If the
     element already has the attribute set, it will be overridden with this value.

     @param tag the tag the enforced attribute is for; the tag will be added to the allowed tag list if necessary
     @param attribute the attribute name
     @param value the enforced attribute value
     @return this, for chaining
     @since 1.24.2
     */
    public Safelist addEnforcedAttribute(Tag tag, String attribute, String value) {
        Validate.notNull(tag);
        Validate.notEmpty(attribute);
        Validate.notEmpty(value);

        TagKey tagKey = TagKey.valueOf(tag);
        tags.add(tagKey);
        return addEnforcedAttribute(tagKey, attribute, value);
    }

    private Safelist addEnforcedAttribute(TagKey tagKey, String attribute, String value) {
        AttributeKey attrKey = AttributeKey.valueOf(attribute);
        AttributeValue attrVal = AttributeValue.valueOf(value);

        Map<AttributeKey, AttributeValue> attrMap = enforcedAttributes.computeIfAbsent(tagKey, k -> new HashMap<>());
        attrMap.put(attrKey, attrVal);
        return this;
    }

    /**
     Remove a previously configured enforced attribute from a tag.

     @param tag   The tag the enforced attribute is for.
     @param attribute   The attribute name
     @return this (for chaining)
     */
    public Safelist removeEnforcedAttribute(String tag, String attribute) {
        Validate.notEmpty(tag);
        Validate.notEmpty(attribute);

        TagKey tagKey = TagKey.valueOf(tag);
        if (tags.contains(tagKey) && enforcedAttributes.containsKey(tagKey)) {
            AttributeKey attrKey = AttributeKey.valueOf(attribute);
            Map<AttributeKey, AttributeValue> attrMap = enforcedAttributes.get(tagKey);
            attrMap.remove(attrKey);

            if (attrMap.isEmpty()) // Remove tag from enforced attribute map if no enforced attributes are present
                enforcedAttributes.remove(tagKey);
        }
        return this;
    }

    /**
     * Configure this Safelist to preserve relative links in an element's URL attribute, or convert them to absolute
     * links. By default, this is <b>false</b>: URLs will be  made absolute (e.g. start with an allowed protocol, like
     * e.g. {@code http://}.
     *
     * @param preserve {@code true} to allow relative links, {@code false} (default) to deny
     * @return this Safelist, for chaining.
     * @see #addProtocols
     */
    public Safelist preserveRelativeLinks(boolean preserve) {
        preserveRelativeLinks = preserve;
        return this;
    }

    /**
     * Get the current setting for preserving relative links.
     * @return {@code true} if relative links are preserved, {@code false} if they are converted to absolute.
     */
    public boolean preserveRelativeLinks() {
        return preserveRelativeLinks;
    }

    /**
     Add allowed URL protocols for an element's URL attribute. This restricts the possible values of the attribute to
     URLs with the defined protocol.
     <p>
     E.g.: <code>addProtocols("a", "href", "ftp", "http", "https")</code>
     </p>
     <p>
     To allow a link to an in-page URL anchor (i.e. <code>&lt;a href="#anchor"&gt;</code>, add a <code>#</code>:<br>
     E.g.: <code>addProtocols("a", "href", "#")</code>
     </p>
     <p>
     To allow base64 encoded image data URIs (i.e. <code>data:image/png;base64,...</code>), add
     <code>data:image</code>.
     </p>

     @param tag       Tag the URL protocol is for
     @param attribute       Attribute name
     @param protocols List of valid protocols
     @return this, for chaining
     */
    public Safelist addProtocols(String tag, String attribute, String... protocols) {
        Validate.notEmpty(tag);
        Validate.notEmpty(attribute);
        Validate.notNull(protocols);

        return addProtocols(TagKey.valueOf(tag), AttributeKey.valueOf(attribute), protocols);
    }

    /**
     Add allowed URL protocols for a namespaced tag's URL attribute.

     @param tag the tag the URL protocol is for
     @param attribute the attribute name
     @param protocols list of valid protocols
     @return this, for chaining
     @since 1.24.2
     */
    public Safelist addProtocols(Tag tag, String attribute, String... protocols) {
        Validate.notNull(tag);
        Validate.notEmpty(attribute);
        Validate.notNull(protocols);

        return addProtocols(TagKey.valueOf(tag), AttributeKey.valueOf(attribute), protocols);
    }

    private Safelist addProtocols(TagKey tagKey, AttributeKey attrKey, String... protocols) {
        Map<AttributeKey, Set<Protocol>> attrMap = this.protocols.computeIfAbsent(tagKey, k -> new HashMap<>());
        Set<Protocol> protSet = attrMap.computeIfAbsent(attrKey, k -> new HashSet<>());

        for (String protocol : protocols) {
            Validate.notEmpty(protocol);
            protSet.add(Protocol.valueOf(protocol));
        }
        return this;
    }

    /**
     Remove allowed URL protocols for an element's URL attribute. If you remove all protocols for an attribute, that
     attribute will allow any protocol.
     <p>
     E.g.: <code>removeProtocols("a", "href", "ftp")</code>
     </p>

     @param tag Tag the URL protocol is for
     @param attribute Attribute name
     @param removeProtocols List of invalid protocols
     @return this, for chaining
     */
    public Safelist removeProtocols(String tag, String attribute, String... removeProtocols) {
        Validate.notEmpty(tag);
        Validate.notEmpty(attribute);
        Validate.notNull(removeProtocols);

        TagKey tagKey = TagKey.valueOf(tag);
        AttributeKey attr = AttributeKey.valueOf(attribute);

        // make sure that what we're removing actually exists; otherwise can open the tag to any data and that can
        // be surprising
        Validate.isTrue(protocols.containsKey(tagKey), "Cannot remove a protocol that is not set.");
        Map<AttributeKey, Set<Protocol>> tagProtocols = protocols.get(tagKey);
        Validate.isTrue(tagProtocols.containsKey(attr), "Cannot remove a protocol that is not set.");

        Set<Protocol> attrProtocols = tagProtocols.get(attr);
        for (String protocol : removeProtocols) {
            Validate.notEmpty(protocol);
            attrProtocols.remove(Protocol.valueOf(protocol));
        }

        if (attrProtocols.isEmpty()) { // Remove protocol set if empty
            tagProtocols.remove(attr);
            if (tagProtocols.isEmpty()) // Remove entry for tag if empty
                protocols.remove(tagKey);
        }
        return this;
    }

    /**
     Configure how elements that are not allowed by this safelist are handled by a {@link Cleaner}: either unwrap them
     (keep their permitted descendants, which is the default and the historical behavior), or discard the entire
     subtree.
     <p>This sets the handling for all elements. Use the overloads to set it per element.</p>

     @param handling the handling to apply to rejected elements
     @return this, for chaining
     @see #rejectedElementHandling(String, RejectedElementHandling)
     @since 1.24.2
     */
    public Safelist rejectedElementHandling(RejectedElementHandling handling) {
        Validate.notNull(handling);
        defaultRejectedHandling = handling;
        return this;
    }

    /**
     Configure how a specific element is handled when it is not allowed by this safelist.
     <p>For example, to discard scripts and their contents entirely, rather than unwrapping them:
     <pre>{@code
     Safelist safelist = Safelist.relaxed5()
         .rejectedElementHandling("script", Safelist.RejectedElementHandling.DiscardSubtree);
     }</pre>

     @param tagName the element name
     @param handling the handling to apply
     @return this, for chaining
     @since 1.24.2
     */
    public Safelist rejectedElementHandling(String tagName, RejectedElementHandling handling) {
        Validate.notEmpty(tagName);
        Validate.notNull(handling);
        rejectedHandling.put(TagKey.valueOf(tagName), handling);
        return this;
    }

    /**
     Configure how a specific namespaced element is handled when it is not allowed by this safelist.

     @param tag the element
     @param handling the handling to apply
     @return this, for chaining
     @since 1.24.2
     */
    public Safelist rejectedElementHandling(Tag tag, RejectedElementHandling handling) {
        Validate.notNull(tag);
        Validate.notNull(handling);
        rejectedHandling.put(TagKey.valueOf(tag), handling);
        return this;
    }

    /**
     Get the handling that will be applied to a rejected element.

     @param tagName the element name
     @return the configured handling, or the default ({@link RejectedElementHandling#Unwrap}) if not specifically set
     @since 1.24.2
     */
    public RejectedElementHandling rejectedElementHandling(String tagName) {
        Validate.notEmpty(tagName);
        return rejectedElementHandling(TagKey.valueOf(tagName));
    }

    /**
     Get the handling that will be applied to a rejected namespaced element.

     @param tag the element
     @return the configured handling, or the default if not specifically set
     @since 1.24.2
     */
    public RejectedElementHandling rejectedElementHandling(Tag tag) {
        Validate.notNull(tag);
        return rejectedElementHandling(TagKey.valueOf(tag));
    }

    private RejectedElementHandling rejectedElementHandling(TagKey tag) {
        RejectedElementHandling handling = rejectedHandling.get(tag);
        if (handling != null) return handling;
        if (tag.namespace != null) {
            handling = rejectedHandling.get(TagKey.of(null, tag.normalName));
            if (handling != null) return handling;
        }
        return defaultRejectedHandling;
    }

    /**
     * Test if the supplied tag is allowed by this safelist, in any namespace.
     * @param tag test tag
     * @return true if allowed
     */
    public boolean isSafeTag(String tag) {
        String normalName = asciiLowerCase(tag);
        for (TagKey key : tags) {
            if (key.normalName.equals(normalName)) return true;
        }
        return false;
    }

    /**
     Test if the supplied tag is allowed by this safelist, considering both its name and namespace.
     <p>A tag configured by name only (via {@link #addTags(String...)}) is allowed in any namespace. A tag configured
     with a {@link Tag} is only allowed in that tag's namespace.</p>

     @param tag test tag
     @return true if allowed
     @since 1.24.2
     */
    public boolean isSafeTag(Tag tag) {
        Validate.notNull(tag);
        if (!isSafeTag(tag.normalName())) return false; // honors Safelist subclass overrides

        boolean nameConfigured = false;
        for (TagKey key : tags) {
            if (!key.normalName.equals(tag.normalName())) continue;
            nameConfigured = true;
            if (key.namespace == null || key.namespace.equals(tag.namespace())) return true;
        }
        // the name was allowed by an overridden isSafeTag(String), rather than by a configured tag key
        return !nameConfigured;
    }

    /**
     Test if the supplied tag name is allowed in the supplied namespace.

     @param tagName test tag name
     @param namespace the namespace
     @return true if allowed
     @since 1.24.2
     */
    public boolean isSafeTag(String tagName, String namespace) {
        Validate.notEmpty(tagName);
        Validate.notNull(namespace);
        String normalName = asciiLowerCase(tagName);
        for (TagKey key : tags) {
            if (!key.normalName.equals(normalName)) continue;
            if (key.namespace == null || key.namespace.equals(namespace)) return true;
        }
        return false;
    }

    /**
     * Test if the supplied attribute is allowed by this safelist for this tag.
     * <p>This method does not modify the input element or attribute.</p>
     * @param tagName tag to consider allowing the attribute in
     * @param el element under test, to confirm protocol and namespace; may be null
     * @param attr attribute under test
     * @return true if allowed
     */
    public boolean isSafeAttribute(String tagName, @Nullable Element el, Attribute attr) {
        Validate.notEmpty(tagName);
        String namespace = el != null ? el.tag().namespace() : null;
        return isSafeAttribute(TagKey.of(namespace, asciiLowerCase(tagName)), el, attr);
    }

    /**
     Test if the supplied attribute is allowed by this safelist for this tag, considering the tag's namespace.

     @param tag tag to consider allowing the attribute in
     @param el element under test, to confirm protocol; may be null
     @param attr attribute under test
     @return true if allowed
     @since 1.24.2
     */
    public boolean isSafeAttribute(Tag tag, @Nullable Element el, Attribute attr) {
        Validate.notNull(tag);
        // delegate through the String overload, so that Safelist subclasses which override it are honored
        return isSafeAttribute(tag.getName(), el, attr);
    }

    private boolean isSafeAttribute(TagKey tag, @Nullable Element el, Attribute attr) {
        AttributeKey key = AttributeKey.valueOf(attr.getKey());

        Set<AttributeKey> okSet = attributesFor(tag);
        AttributeKey matched = matchingKey(okSet, key);
        if (matched != null) {
            Set<Protocol> attrProts = protocolsFor(tag, matched);
            // ok if not defined protocol; otherwise test
            return attrProts == null || isSafeProtocol(getProtocolValue(el, attr), attrProts);
        }

        Map<AttributeKey, AttributeValue> enforcedSet = enforcedAttributesFor(tag);
        if (enforcedSet != null) {
            for (Map.Entry<AttributeKey, AttributeValue> entry : enforcedSet.entrySet()) {
                if (entry.getKey().matches(key)) {
                    // enforced attr key was LCed via AttributeKey.valueOf(attr.getKey()),
                    // if the input already has that exact value, treat it as safe
                    return entry.getValue().equals(AttributeValue.valueOf(attr.getValue()));
                }
            }
        }

        // no attributes defined for tag, try :all tag
        if (tag.normalName.equals(All)) return false;
        return isSafeAttribute(TagKey.of(tag.namespace, All), el, attr)
            || (tag.namespace != null && isSafeAttribute(TagKey.of(null, All), el, attr));
    }

    /** Gets the attributes configured for the tag, checking the exact namespace then any namespace. */
    private @Nullable Set<AttributeKey> attributesFor(TagKey tag) {
        Set<AttributeKey> set = attributes.get(tag);
        if (set == null && tag.namespace != null) set = attributes.get(TagKey.of(null, tag.normalName));
        if (set == null && tag.namespace == null) set = unionAttributes(tag.normalName);
        return set;
    }

    private @Nullable Set<AttributeKey> unionAttributes(String normalName) {
        Set<AttributeKey> union = null;
        for (Map.Entry<TagKey, Set<AttributeKey>> entry : attributes.entrySet()) {
            if (!entry.getKey().normalName.equals(normalName)) continue;
            if (union == null) union = new HashSet<>();
            union.addAll(entry.getValue());
        }
        return union;
    }

    private @Nullable Map<AttributeKey, AttributeValue> enforcedAttributesFor(TagKey tag) {
        Map<AttributeKey, AttributeValue> map = enforcedAttributes.get(tag);
        if (map == null && tag.namespace != null) map = enforcedAttributes.get(TagKey.of(null, tag.normalName));
        if (map == null && tag.namespace == null) {
            Map<AttributeKey, AttributeValue> union = null;
            for (Map.Entry<TagKey, Map<AttributeKey, AttributeValue>> entry : enforcedAttributes.entrySet()) {
                if (!entry.getKey().normalName.equals(tag.normalName)) continue;
                if (union == null) union = new HashMap<>();
                union.putAll(entry.getValue());
            }
            map = union;
        }
        return map;
    }

    /** Finds an exact or wildcard matching key in the set, or null if none match. */
    private static @Nullable AttributeKey matchingKey(@Nullable Set<AttributeKey> keys, AttributeKey key) {
        if (keys == null) return null;
        if (keys.contains(key)) return key;
        for (AttributeKey candidate : keys) {
            if (candidate.matches(key)) return candidate;
        }
        return null;
    }

    private @Nullable Set<Protocol> protocolsFor(TagKey tag, AttributeKey key) {
        Map<AttributeKey, Set<Protocol>> map = protocols.get(tag);
        if (map == null && tag.namespace != null) map = protocols.get(TagKey.of(null, tag.normalName));
        if (map == null && tag.namespace == null) {
            for (Map.Entry<TagKey, Map<AttributeKey, Set<Protocol>>> entry : protocols.entrySet()) {
                if (!entry.getKey().normalName.equals(tag.normalName)) continue;
                Set<Protocol> found = protocolsFor(entry.getKey(), key);
                if (found != null) return found;
            }
        }
        if (map == null) return null;
        Set<Protocol> set = map.get(key);
        if (set != null) return set;
        for (Map.Entry<AttributeKey, Set<Protocol>> entry : map.entrySet()) {
            if (entry.getKey().matches(key)) return entry.getValue();
        }
        return null;
    }

    private String getProtocolValue(@Nullable Element el, Attribute attr) {
        String value = el != null ? el.absUrl(attr.getKey()) : "";
        if (value.isEmpty() && !StringUtil.hasHttpScheme(attr.getValue()))
            value = attr.getValue(); // if it could not be made abs, run as-is to allow custom unknown protocols
        return value;
    }

    private boolean isSafeProtocol(String value, Set<Protocol> protocols) {
        for (Protocol protocol : protocols) {
            String prot = protocol.toString();

            if (prot.equals("#")) { // allows anchor links
                if (isValidAnchor(value)) return true;
                continue;
            }

            if (prot.equals("data:image")) { // allows only base64 encoded image data URIs
                if (isValidDataImage(value)) return true;
                continue;
            }

            String lc = lowerCase(value);
            if (lc.startsWith(prot)
                && lc.length() > prot.length()
                && lc.charAt(prot.length()) == ':') {
                return true;
            }
        }
        return false;
    }

    /**
     Check if a URL attribute should be normalized to an absolute URL in the cleaned output. Uses the configured
     protocols for that tag+attribute pair, falling back to {@code :all} only if the tag does not define the
     attribute.
     */
    boolean shouldAbsUrl(String tagName, String attrKey) {
        if (preserveRelativeLinks) return false;
        return shouldAbsUrl(TagKey.valueOf(tagName), AttributeKey.valueOf(attrKey));
    }

    /**
     Check if a URL attribute on a namespaced tag should be normalized to an absolute URL in the cleaned output.
     @since 1.24.2
     */
    public boolean shouldAbsUrl(Tag tag, String attrKey) {
        if (preserveRelativeLinks) return false;
        return shouldAbsUrl(TagKey.valueOf(tag), AttributeKey.valueOf(attrKey));
    }

    private boolean shouldAbsUrl(TagKey tag, AttributeKey key) {
        Set<AttributeKey> allowedAttrs = attributesFor(tag);
        AttributeKey matched = matchingKey(allowedAttrs, key);
        if (matched != null)
            return protocolsFor(tag, matched) != null;

        Map<AttributeKey, AttributeValue> enforcedAttrs = enforcedAttributesFor(tag);
        if (enforcedAttrs != null) {
            for (AttributeKey enforced : enforcedAttrs.keySet()) {
                if (enforced.matches(key)) return false;
            }
        }

        if (tag.normalName.equals(All)) return false;
        return shouldAbsUrl(TagKey.of(tag.namespace, All), key)
            || (tag.namespace != null && shouldAbsUrl(TagKey.of(null, All), key));
    }

    private static boolean isValidAnchor(String value) {
        return value.startsWith("#") && !value.matches(".*\\s.*");
    }

    /** Tests that a data URI contains a base64 encoded image, and no whitespace-separated junk. */
    static boolean isValidDataImage(String value) {
        String lc = lowerCase(value);
        if (!lc.startsWith("data:image/")) return false;
        int comma = lc.indexOf(',');
        if (comma < 0) return false;
        String header = lc.substring("data:".length(), comma);
        if (!header.contains(";base64")) return false;
        String data = value.substring(comma + 1);
        if (data.isEmpty()) return false;
        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '=';
            if (!ok) return false;
        }
        return true;
    }

    /**
     Gets the Attributes that should be enforced for a given tag
     * @param tagName the tag
     * @return the attributes that will be enforced; empty if none are set for the given tag
     */
    public Attributes getEnforcedAttributes(String tagName) {
        return getEnforcedAttributes(TagKey.valueOf(tagName));
    }

    /**
     Gets the Attributes that should be enforced for a given namespaced tag.

     @param tag the tag
     @return the attributes that will be enforced; empty if none are set for the given tag
     @since 1.24.2
     */
    public Attributes getEnforcedAttributes(Tag tag) {
        Validate.notNull(tag);
        return getEnforcedAttributes(TagKey.valueOf(tag));
    }

    private Attributes getEnforcedAttributes(TagKey tag) {
        Attributes attrs = new Attributes();
        Map<AttributeKey, AttributeValue> keyVals = enforcedAttributesFor(tag);
        if (keyVals != null) {
            for (Map.Entry<AttributeKey, AttributeValue> entry : keyVals.entrySet()) {
                attrs.put(entry.getKey().toString(), entry.getValue().toString());
            }
        }
        return attrs;
    }

    // named types for config. All just hold strings, but here for my sanity.

    /** A tag key, by namespace and normal name. A null namespace matches any namespace. */
    static class TagKey {
        final @Nullable String namespace;
        final String normalName;

        private TagKey(@Nullable String namespace, String normalName) {
            this.namespace = namespace;
            this.normalName = normalName;
        }

        static TagKey of(@Nullable String namespace, String normalName) {
            return new TagKey(namespace, normalName);
        }

        static TagKey valueOf(String tagName) {
            return new TagKey(null, asciiLowerCase(tagName));
        }

        static TagKey valueOf(Tag tag) {
            return new TagKey(tag.namespace(), tag.normalName());
        }

        @Override public int hashCode() {
            return Objects.hash(namespace, normalName);
        }

        @Override public boolean equals(@Nullable Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof TagKey)) return false;
            TagKey other = (TagKey) obj;
            return Objects.equals(namespace, other.namespace) && normalName.equals(other.normalName);
        }

        @Override public String toString() {
            return namespace != null ? "{" + namespace + "}" + normalName : normalName;
        }
    }

    static class TagName extends TypedValue {
        TagName(String value) {
            super(value);
        }

        static TagName valueOf(String value) {
            return new TagName(Normalizer.asciiLowerCase(value));
        }
    }

    static class AttributeKey extends TypedValue {
        AttributeKey(String value) {
            super(value);
        }

        static AttributeKey valueOf(String value) {
            return new AttributeKey(Normalizer.asciiLowerCase(value));
        }

        /** Tests if this key was configured as a wildcard (ends with an asterisk). */
        boolean isWildcard() {
            return toString().endsWith("*");
        }

        /** Tests if this key matches the supplied concrete key, honoring wildcards. */
        boolean matches(AttributeKey key) {
            String value = toString();
            if (value.endsWith("*")) return key.toString().startsWith(value.substring(0, value.length() - 1));
            return value.equals(key.toString());
        }
    }

    static class AttributeValue extends TypedValue {
        AttributeValue(String value) {
            super(value);
        }

        static AttributeValue valueOf(String value) {
            return new AttributeValue(value);
        }
    }

    static class Protocol extends TypedValue {
        Protocol(String value) {
            super(value);
        }

        static Protocol valueOf(String value) {
            return new Protocol(value);
        }
    }

    abstract static class TypedValue {
        private final String value;

        TypedValue(String value) {
            Validate.notNull(value);
            this.value = value;
        }

        @Override
        public int hashCode() {
            return value.hashCode();
        }

        @Override
        public boolean equals(@Nullable Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            TypedValue other = (TypedValue) obj;
            return Objects.equals(value, other.value);
        }

        @Override
        public String toString() {
            return value;
        }
    }
}
