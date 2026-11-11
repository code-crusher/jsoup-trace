package org.jsoup.safety;

import org.jsoup.helper.Validate;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.DataNode;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.NodeInternals;
import org.jsoup.nodes.Range;
import org.jsoup.nodes.TextNode;
import org.jsoup.parser.ParseErrorList;
import org.jsoup.parser.Parser;
import org.jsoup.parser.Tag;
import org.jspecify.annotations.Nullable;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import static org.jsoup.internal.SharedConstants.DummyUri;

/**
 The {@link Safelist}-based HTML cleaner. Use to ensure that end-user provided HTML contains only the elements and attributes
 that you are expecting; no junk, and no cross-site scripting attacks!
 <p>
 The HTML cleaner parses the input as HTML and then runs it through a safelist, so the output HTML can only contain
 HTML that is allowed by the safelist.
 </p>
 <p>
 It is assumed that the input HTML is a body fragment; the clean methods only pull from the source's body, and the
 canned safelists only allow body-contained tags.
 </p>
 <p>
 Rather than interacting directly with a Cleaner object, generally see the {@code clean} methods in {@link org.jsoup.Jsoup}.
 </p>
 <p>
 A Cleaner may also be supplied to a {@link Parser} (via {@link Parser#cleaner(Cleaner)}), in which case input is
 cleaned as it is parsed, in a single pass. That supports any regular parser input (a string, file, connection, or
 reader), and either the HTML or XML {@link Document.OutputSettings.Syntax syntax}. See {@link #clean(Element)} for
 cleaning an already-parsed fragment.
 </p>
 <p>
 A Cleaner may be reused across multiple documents and shared across concurrent threads once its {@link Safelist} has
 been configured. The cleaner uses the supplied safelist directly, so later safelist changes affect later cleaning
 calls. If you need a variant of an existing configuration, use {@link Safelist#Safelist(Safelist)} to make a copy.
 </p>
 */
public class Cleaner {
    private final Safelist safelist;

    /**
     Create a new cleaner, that sanitizes documents using the supplied safelist.
     @param safelist safe-list to clean with
     */
    public Cleaner(Safelist safelist) {
        Validate.notNull(safelist);
        this.safelist = safelist;
    }

    /**
     Get the safelist this cleaner is using.
     @return the safelist
     @since 1.24.2
     */
    public Safelist safelist() {
        return safelist;
    }

    /**
     Creates a new, clean document, from the original dirty document, containing only elements allowed by the safelist.
     The original document is not modified. Only elements from the dirty document's <code>body</code> are used. The
     OutputSettings of the original document are cloned into the clean document.
     @param dirtyDocument Untrusted base document to clean.
     @return cleaned document.
     */
    public Document clean(Document dirtyDocument) {
        return clean(dirtyDocument, null);
    }

    /**
     Creates a new, clean document, from the original dirty document, containing only elements allowed by the safelist.
     The original document is not modified. Only elements from the dirty document's <code>body</code> are used. The
     OutputSettings of the original document are cloned into the clean document.
     @param dirtyDocument Untrusted base document to clean.
     @param errors if not null, will be populated with the detailed cleaning errors (dropped tags and attributes, and
     added attributes)
     @return cleaned document.
     @since 1.24.2
     */
    public Document clean(Document dirtyDocument, @Nullable CleaningErrors errors) {
        Validate.notNull(dirtyDocument);
        if (errors != null) errors.clear();

        Document clean = Document.createShell(dirtyDocument.baseUri());
        copySafeNodes(dirtyDocument.body(), clean.body(), errors);
        clean.outputSettings(dirtyDocument.outputSettings().clone());

        return clean;
    }

    /**
     Creates a new, clean element, from the original dirty element, containing only elements allowed by the safelist.
     The original element is not modified. This method is suitable for cleaning a fragment (such as a {@code body} or
     {@code div} element), in either HTML or XML.
     <p>The returned element is a shallow clone of the source. If the source element itself is allowed by the safelist,
     its safe attributes (and any enforced attributes) are applied; if it is not allowed, it is retained as the
     container for the cleaned children, without its attributes.</p>

     @param dirtyElement the untrusted element to clean
     @return the cleaned element
     @since 1.24.2
     */
    public Element clean(Element dirtyElement) {
        return clean(dirtyElement, null);
    }

    /**
     Creates a new, clean element, from the original dirty element, containing only elements allowed by the safelist.
     The original element is not modified.

     @param dirtyElement the untrusted element to clean
     @param errors if not null, will be populated with the detailed cleaning errors
     @return the cleaned element
     @since 1.24.2
     */
    public Element clean(Element dirtyElement, @Nullable CleaningErrors errors) {
        Validate.notNull(dirtyElement);
        if (errors != null) errors.clear();

        Element clean = safelist.isSafeTag(dirtyElement.tag())
            ? createSafeElement(dirtyElement, errors).el
            : clearAttributes(dirtyElement.shallowClone());

        copyChildren(dirtyElement, clean, errors);
        return clean;
    }

    /**
     Determines if the input document's <b>body</b> is valid, against the safelist. It is considered valid if all the
     tags and attributes in the input HTML are allowed by the safelist, and that there is no content in the
     <code>head</code>.
     <p>
     This method is intended to be used in a user interface as a validator for user input. Note that regardless of the
     output of this method, the input document <b>must always</b> be normalized using a method such as
     {@link #clean(Document)}, and the result of that method used to store or serialize the document before later reuse
     such as presentation to end users. This ensures that enforced attributes are set correctly, and that any
     differences between how a given browser and how jsoup parses the input HTML are normalized.
     </p>
     <p>Example:
     <pre>{@code
     Document inputDoc = Jsoup.parse(inputHtml);
     Cleaner cleaner = new Cleaner(Safelist.relaxed());
     boolean isValid = cleaner.isValid(inputDoc);
     Document normalizedDoc = cleaner.clean(inputDoc);
     }</pre>
     </p>
     @param dirtyDocument document to test
     @return true if no tags or attributes need to be removed; false if they do
     */
    public boolean isValid(Document dirtyDocument) {
        return isValid(dirtyDocument, null);
    }

    /**
     Determines if the input document's <b>body</b> is valid, against the safelist. It is considered valid if all the
     tags and attributes in the input HTML are allowed by the safelist, and that there is no content in the
     <code>head</code>.
     <p>Additionally, if the document's parser has parse error tracking enabled and recorded errors for the parse, those
     parse errors are considered: a document with parse errors is not valid.</p>

     @param dirtyDocument document to test
     @param errors if not null, will be populated with the detailed cleaning errors
     @return true if no tags or attributes need to be removed; false if they do
     @since 1.24.2
     @see Parser#setTrackErrors(int)
     */
    public boolean isValid(Document dirtyDocument, @Nullable CleaningErrors errors) {
        Validate.notNull(dirtyDocument);
        CleaningErrors counted = errors != null ? errors : new CleaningErrors();
        if (errors != null) errors.clear();

        Document clean = Document.createShell(dirtyDocument.baseUri());
        copySafeNodes(dirtyDocument.body(), clean.body(), counted);
        boolean valid = counted.numDropped() == 0
            && dirtyDocument.head().childNodes().isEmpty(); // because we only look at the body, but we start from a shell, make sure there's nothing in the head

        Parser parser = dirtyDocument.parser();
        if (valid && parser.isTrackErrors() && !parser.getErrors().isEmpty())
            valid = false; // parse errors count against validity
        return valid;
    }

    /**
     Determines if the input document's <b>body HTML</b> is valid, against the safelist. It is considered valid if all
     the tags and attributes in the input HTML are allowed by the safelist.
     <p>
     This method is intended to be used in a user interface as a validator for user input. Note that regardless of the
     output of this method, the input document <b>must always</b> be normalized using a method such as
     {@link #clean(Document)}, and the result of that method used to store or serialize the document before later reuse
     such as presentation to end users. This ensures that enforced attributes are set correctly, and that any
     differences between how a given browser and how jsoup parses the input HTML are normalized.
     </p>
     <p>Example:
     <pre>{@code
     Document inputDoc = Jsoup.parse(inputHtml);
     Cleaner cleaner = new Cleaner(Safelist.relaxed());
     boolean isValid = cleaner.isValidBodyHtml(inputHtml);
     Document normalizedDoc = cleaner.clean(inputDoc);
     }</pre>
     </p>
     @param bodyHtml HTML fragment to test
     @return true if no tags or attributes need to be removed; false if they do
     */
    public boolean isValidBodyHtml(String bodyHtml) {
        return isValidBodyHtml(bodyHtml, null);
    }

    /**
     Determines if the input document's <b>body HTML</b> is valid, against the safelist. It is considered valid if all
     the tags and attributes in the input HTML are allowed by the safelist, and the input parses without error.

     @param bodyHtml HTML fragment to test
     @param errors if not null, will be populated with the detailed cleaning errors
     @return true if no tags or attributes need to be removed; false if they do
     @since 1.24.2
     */
    public boolean isValidBodyHtml(String bodyHtml, @Nullable CleaningErrors errors) {
        Validate.notNull(bodyHtml);
        CleaningErrors counted = errors != null ? errors : new CleaningErrors();
        if (errors != null) errors.clear();

        String baseUri = (safelist.preserveRelativeLinks()) ? DummyUri : ""; // fake base URI to allow relative URLs to remain valid
        Document clean = Document.createShell(baseUri);
        Document dirty = Document.createShell(baseUri);
        ParseErrorList errorList = ParseErrorList.tracking(1);
        List<Node> nodes = Parser.parseFragment(bodyHtml, dirty.body(), baseUri, errorList);
        dirty.body().insertChildren(0, nodes);
        copySafeNodes(dirty.body(), clean.body(), counted);
        return counted.numDropped() == 0 && errorList.isEmpty();
    }

    /** Copies the safe children of the source element into the destination element. */
    private void copySafeNodes(Element source, Element dest, @Nullable CleaningErrors errors) {
        copyChildren(source, dest, errors);
    }

    private void copyChildren(Element source, Element dest, @Nullable CleaningErrors errors) {
        // snapshot, as the recursion appends to a different tree (but be safe if a caller mutated the source)
        for (Node child = source.firstChild(); child != null; ) {
            Node next = child.nextSibling();
            copyNode(child, dest, errors);
            child = next;
        }
    }

    /** Copies a single node (and, if allowed, its descendants) from the source tree into the destination element. */
    private void copyNode(Node source, Element destination, @Nullable CleaningErrors errors) {
        if (source instanceof Element) {
            Element sourceEl = (Element) source;
            Tag sourceTag = sourceEl.tag();

            if (safelist.isSafeTag(sourceTag)) { // safe, clone and copy safe attrs
                Element destChild = createSafeElement(sourceEl, errors).el;
                destination.appendChild(destChild);
                copyChildren(sourceEl, destChild, errors);
                return;
            }

            // not a safe tag
            if (errors != null) errors.tagDropped(sourceEl.tagName());
            if (safelist.rejectedElementHandling(sourceTag) == Safelist.RejectedElementHandling.DiscardSubtree)
                return; // drop the entire subtree
            copyChildren(sourceEl, destination, errors); // unwrap: keep permitted descendants
            return;
        }

        if (source instanceof TextNode) {
            TextNode sourceText = (TextNode) source;
            destination.appendChild(new TextNode(sourceText.getWholeText()));
            return;
        }

        if (source instanceof DataNode) {
            Node parent = source.parentNode();
            if (parent instanceof Element && safelist.isSafeTag(((Element) parent).tag())) {
                destination.appendChild(new DataNode(((DataNode) source).getWholeData()));
                return;
            }
        }

        // else, we don't care about comments, xml proc instructions, etc
        if (errors != null) errors.nodeDropped(source.nodeName());
    }

    private static Element clearAttributes(Element el) {
        el.clearAttributes();
        return el;
    }

    private ElementMeta createSafeElement(Element sourceEl, @Nullable CleaningErrors errors) {
        Element dest = sourceEl.shallowClone(); // reuses tag, clones attributes and preserves any user data
        String sourceTag = sourceEl.tagName();
        Tag sourceTagObj = sourceEl.tag();
        Attributes destAttrs = dest.attributes();
        dest.clearAttributes(); // clear all non-internal attributes, ready for safe copy

        Attributes sourceAttrs = sourceEl.attributes();
        for (Attribute sourceAttr : sourceAttrs) {
            if (safelist.isSafeAttribute(sourceTagObj, sourceEl, sourceAttr)) { // will keep this attr
                String key = sourceAttr.getKey();
                String value = sourceAttr.getValue();

                if (safelist.shouldAbsUrl(sourceTagObj, key)) { // configured to make absolute urls for this key (href)
                    value = sourceEl.absUrl(key);
                    if (value.isEmpty()) // could not be made abs; leave as-is to allow custom unknown protocols
                        value = sourceAttr.getValue();
                }
                Range.AttributeRange range = sourceAttrs.sourceRange(key);
                destAttrs.put(key, value);
                NodeInternals.attributeRange(destAttrs, key, range);
            } else if (errors != null) {
                errors.attributeDropped(sourceTag, sourceAttr.getKey());
            }
        }

        Attributes enforcedAttrs = safelist.getEnforcedAttributes(sourceTagObj);
        // special case for <a href rel=nofollow>, only apply to external links:
        if (sourceEl.nameIs("a") && enforcedAttrs.get("rel").equals("nofollow")) {
            String href = sourceEl.absUrl("href");
            if (!href.isEmpty()) {
                try {
                    URL baseUrl = new URL(sourceEl.baseUri());
                    URL linkUrl = new URL(href);
                    String baseHost = baseUrl.getHost();
                    if (!baseHost.isEmpty() && baseHost.equalsIgnoreCase(linkUrl.getHost())) // same site, so don't set the nofollow
                        enforcedAttrs.remove("rel");
                } catch (MalformedURLException ignored) {}
            }
        }

        // apply enforced attributes case-insensitively, so a preserved-case source attr is canonicalized to the enforced key
        for (Attribute enforcedAttr : enforcedAttrs) {
            String key = enforcedAttr.getKey();
            String value = enforcedAttr.getValue();
            destAttrs.removeIgnoreCase(key);
            destAttrs.put(key, value);
            if (errors != null && !value.equals(sourceAttrs.getIgnoreCase(key)))
                errors.attributeAdded(sourceTag, key, value); // only report a change, not a re-assertion of the input value
        }
        dest.attributes().addAll(destAttrs); // re-attach, if removed in clear
        return new ElementMeta(dest);
    }

    private static class ElementMeta {
        final Element el;

        ElementMeta(Element el) {
            this.el = el;
        }
    }
}
