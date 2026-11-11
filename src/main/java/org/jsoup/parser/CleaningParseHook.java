package org.jsoup.parser;

import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.DataNode;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.CleaningErrors;
import org.jsoup.safety.Safelist;
import org.jspecify.annotations.Nullable;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.jsoup.parser.Parser.NamespaceHtml;

/**
 Applies a {@link Cleaner} to a document as it is built by a {@link TreeBuilder}, so that tokenization, tree construction,
 and sanitization happen in one pass. Rejected nodes are removed from (or unwrapped within) the tree as they are closed,
 so the resulting Document contains only safe content.
 <p>Cleaning is applied bottom-up: an element's descendants are cleaned before the element itself is closed. That makes
 unwrapping safe, as the descendants are already validated.</p>
 <p>This is an internal implementation detail of {@link Parser#cleaner(Cleaner)}.</p>
 */
class CleaningParseHook {
    private final Safelist safelist;
    private final @Nullable CleaningErrors errors;

    CleaningParseHook(Cleaner cleaner, @Nullable CleaningErrors errors) {
        this.safelist = cleaner.safelist();
        this.errors = errors;
    }

    /** Called as each node is inserted, before any node listener. */
    void head(Node node) {
        if (node instanceof Element) return; // elements are handled at close, when fully built
        if (node instanceof TextNode) return; // text is always safe (and may be unwrapped from a rejected parent)

        if (node instanceof DataNode) { // e.g. script / style content; only safe if the parent element is safe
            Node parent = node.parentNode();
            if (!(parent instanceof Element) || !safelist.isSafeTag(((Element) parent).tag())) {
                node.remove();
                if (errors != null) errors.nodeDropped(node.nodeName());
            }
            return;
        }

        // comments, doctypes, processing instructions, xml declarations, etc. are not kept
        node.remove();
        if (errors != null) errors.nodeDropped(node.nodeName());
    }

    /** Called as each node is closed, before any node listener. */
    void tail(Node node) {
        if (!(node instanceof Element)) return;
        Element el = (Element) node;
        if (el instanceof Document) return; // the root document is the container

        boolean safe = safelist.isSafeTag(el.tag());

        if (isStructural(el)) {
            // the html / body containers (and the root element) are always retained, like the Cleaner's output shell
            if (isHtmlHead(el) && !safe) {
                discardChildren(el); // the head is metadata, not body content; drop it unless explicitly allowed
                el.clearAttributes();
                return;
            }
            if (safe)
                applySafeAttributes(el);
            else
                el.clearAttributes(); // not allowed, but retained as a container; drop its attributes
            return;
        }

        if (safe) {
            applySafeAttributes(el);
            return;
        }

        if (errors != null) errors.tagDropped(el.tagName());
        if (safelist.rejectedElementHandling(el.tag()) == Safelist.RejectedElementHandling.DiscardSubtree)
            el.remove();
        else
            el.unwrap(); // children were already cleaned, so retain them
    }

    private void discardChildren(Element el) {
        if (errors != null) {
            for (Node child : el.childNodes()) recordDropped(child);
        }
        el.empty();
    }

    private void recordDropped(Node node) {
        if (node instanceof Element) {
            errors.tagDropped(((Element) node).tagName());
            for (Node child : node.childNodes()) recordDropped(child);
        } else if (!(node instanceof TextNode)) {
            errors.nodeDropped(node.nodeName());
        }
    }

    /** Tests if the element is one of the document's structural containers (html, head, body, or the root element). */
    private static boolean isStructural(Element el) {
        Node parent = el.parent();
        if (parent instanceof Document) return true; // the root element, e.g. html (or the XML root)
        if (parent instanceof Element) {
            Element parentEl = (Element) parent;
            if (parentEl.parent() instanceof Document && parentEl.tag().namespace().equals(NamespaceHtml)
                && parentEl.normalName().equals("html"))
                return el.normalName().equals("head") || el.normalName().equals("body");
        }
        return false;
    }

    private static boolean isHtmlHead(Element el) {
        return el.normalName().equals("head") && el.tag().namespace().equals(NamespaceHtml);
    }

    /** Filters the element's attributes in place, absolutizes URL attributes, and applies any enforced attributes. */
    private void applySafeAttributes(Element el) {
        Attributes attrs = el.attributes();
        Tag tag = el.tag();
        String tagName = el.tagName();

        // drop attributes that are not allowed
        List<String> dropped = null;
        for (Attribute attr : attrs) {
            if (!safelist.isSafeAttribute(tag, el, attr)) {
                if (dropped == null) dropped = new ArrayList<>();
                dropped.add(attr.getKey());
            }
        }
        if (dropped != null) {
            for (String key : dropped) {
                if (errors != null) errors.attributeDropped(tagName, key);
                attrs.remove(key);
            }
        }

        // absolutize configured URL attributes
        List<String[]> absolute = null;
        for (Attribute attr : attrs) {
            String key = attr.getKey();
            if (safelist.shouldAbsUrl(tag, key)) {
                String value = el.absUrl(key);
                if (!value.isEmpty() && !value.equals(attr.getValue())) {
                    if (absolute == null) absolute = new ArrayList<>();
                    absolute.add(new String[]{key, value});
                }
            }
        }
        if (absolute != null) {
            for (String[] update : absolute) attrs.put(update[0], update[1]);
        }

        // apply enforced attributes
        Attributes enforcedAttrs = safelist.getEnforcedAttributes(tag);
        if (el.nameIs("a") && enforcedAttrs.get("rel").equals("nofollow")) {
            String href = el.absUrl("href");
            if (!href.isEmpty()) {
                try {
                    URL baseUrl = new URL(el.baseUri());
                    URL linkUrl = new URL(href);
                    String baseHost = baseUrl.getHost();
                    if (!baseHost.isEmpty() && baseHost.equalsIgnoreCase(linkUrl.getHost()))
                        enforcedAttrs.remove("rel"); // same site, so don't set the nofollow
                } catch (MalformedURLException ignored) {}
            }
        }
        for (Attribute enforced : enforcedAttrs) {
            String key = enforced.getKey();
            String value = enforced.getValue();
            if (!value.equals(attrs.getIgnoreCase(key))) {
                if (errors != null) errors.attributeAdded(tagName, key, value);
            }
            attrs.put(key, value);
        }
    }
}
