package org.jsoup.safety;

import org.jsoup.helper.Validate;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 Records the detailed results of a {@link Cleaner} pass: which elements were dropped, which attributes were dropped, and
 which attributes were added or changed by enforced attribute rules.
 <p>A {@code CleaningErrors} instance is supplied to a cleaning call, and is populated as the input is cleaned. For
 example:</p>
 <pre>{@code
 Cleaner cleaner = new Cleaner(Safelist.relaxed());
 CleaningErrors errors = new CleaningErrors();
 Document clean = cleaner.clean(dirtyDocument, errors);
 for (CleaningErrors.DroppedTag tag : errors.droppedTags())
     System.out.println("Dropped element: " + tag.tagName());
 }</pre>
 <p>An instance may be reused for another cleaning pass by calling {@link #clear()} first.</p>

 @since 1.24.2
 */
public class CleaningErrors {
    private final List<DroppedTag> droppedTags = new ArrayList<>();
    private final List<DroppedNode> droppedNodes = new ArrayList<>();
    private final List<DroppedAttribute> droppedAttributes = new ArrayList<>();
    private final List<AddedAttribute> addedAttributes = new ArrayList<>();

    /** Create a new, empty, cleaning error list. */
    public CleaningErrors() {
    }

    /**
     Get the elements that were dropped (rejected) by the safelist, in the order they were dropped.

     @return the dropped elements
     */
    public List<DroppedTag> droppedTags() {
        return Collections.unmodifiableList(droppedTags);
    }

    /**
     Get the non-element nodes (such as comments, processing instructions, and data nodes) that were dropped, in the
     order they were dropped.

     @return the dropped nodes
     */
    public List<DroppedNode> droppedNodes() {
        return Collections.unmodifiableList(droppedNodes);
    }

    /**
     Get the attributes that were dropped (rejected) by the safelist, in the order they were dropped.

     @return the dropped attributes
     */
    public List<DroppedAttribute> droppedAttributes() {
        return Collections.unmodifiableList(droppedAttributes);
    }

    /**
     Get the attributes that were added or changed by the safelist's enforced attribute rules, in the order they were
     applied.

     @return the added attributes
     */
    public List<AddedAttribute> addedAttributes() {
        return Collections.unmodifiableList(addedAttributes);
    }

    /**
     Get the total number of cleaning changes recorded (dropped elements, nodes, and attributes, and added attributes).

     @return the number of changes
     */
    public int size() {
        return droppedTags.size() + droppedNodes.size() + droppedAttributes.size() + addedAttributes.size();
    }

    /**
     Get the number of dropped (rejected) elements, nodes, and attributes. Added enforced attributes are not counted, as
     they do not make the input invalid.

     @return the number of dropped elements, nodes, and attributes
     */
    public int numDropped() {
        return droppedTags.size() + droppedNodes.size() + droppedAttributes.size();
    }

    /**
     Test if no cleaning changes were recorded.

     @return true if the input was fully valid against the safelist
     */
    public boolean isEmpty() {
        return size() == 0;
    }

    /**
     Test if no elements, nodes, or attributes were dropped. This is the test used to determine input validity; enforced
     attributes that are added do not count against validity.

     @return true if no elements, nodes, or attributes were dropped
     */
    public boolean isDroppedEmpty() {
        return numDropped() == 0;
    }

    /** Clear all recorded errors, so this instance can be reused for another cleaning pass. */
    public void clear() {
        droppedTags.clear();
        droppedNodes.clear();
        droppedAttributes.clear();
        addedAttributes.clear();
    }

    /**
     Record a dropped element. Used internally by the {@link Cleaner}, and by the in-parse cleaning.
     @param tagName the dropped element's name
     */
    public void tagDropped(String tagName) {
        Validate.notNull(tagName);
        droppedTags.add(new DroppedTag(tagName));
    }

    /**
     Record a dropped non-element node (e.g. a comment or data node). Used internally by the {@link Cleaner}, and by
     the in-parse cleaning.
     @param nodeName the dropped node's name
     */
    public void nodeDropped(String nodeName) {
        Validate.notNull(nodeName);
        droppedNodes.add(new DroppedNode(nodeName));
    }

    /**
     Record a dropped attribute. Used internally by the {@link Cleaner}, and by the in-parse cleaning.
     @param tagName the element's name
     @param attributeKey the dropped attribute's key
     */
    public void attributeDropped(String tagName, String attributeKey) {
        Validate.notNull(tagName);
        Validate.notNull(attributeKey);
        droppedAttributes.add(new DroppedAttribute(tagName, attributeKey));
    }

    /**
     Record an added (or changed) enforced attribute. Used internally by the {@link Cleaner}, and by the in-parse
     cleaning.
     @param tagName the element's name
     @param attributeKey the added attribute's key
     @param value the enforced value
     */
    public void attributeAdded(String tagName, String attributeKey, @Nullable String value) {
        Validate.notNull(tagName);
        Validate.notNull(attributeKey);
        addedAttributes.add(new AddedAttribute(tagName, attributeKey, value));
    }

    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        for (DroppedTag tag : droppedTags) sb.append("Dropped tag: ").append(tag).append('\n');
        for (DroppedNode node : droppedNodes) sb.append("Dropped node: ").append(node).append('\n');
        for (DroppedAttribute attr : droppedAttributes) sb.append("Dropped attribute: ").append(attr).append('\n');
        for (AddedAttribute attr : addedAttributes) sb.append("Added attribute: ").append(attr).append('\n');
        return sb.toString();
    }

    /** A non-element node that was dropped by the safelist. */
    public static class DroppedNode {
        private final String nodeName;

        DroppedNode(String nodeName) {
            this.nodeName = nodeName;
        }

        /** Get the name of the dropped node (e.g. {@code #comment} or {@code #data}). */
        public String nodeName() {
            return nodeName;
        }

        @Override public String toString() {
            return nodeName;
        }
    }

    /** An element that was dropped by the safelist. */
    public static class DroppedTag {
        private final String tagName;

        DroppedTag(String tagName) {
            this.tagName = tagName;
        }

        /** Get the name of the dropped element, in its original case as parsed. */
        public String tagName() {
            return tagName;
        }

        @Override public String toString() {
            return tagName;
        }
    }

    /** An attribute that was dropped by the safelist. */
    public static class DroppedAttribute {
        private final String tagName;
        private final String attributeKey;

        DroppedAttribute(String tagName, String attributeKey) {
            this.tagName = tagName;
            this.attributeKey = attributeKey;
        }

        /** Get the name of the element the dropped attribute was on. */
        public String tagName() {
            return tagName;
        }

        /** Get the key of the dropped attribute. */
        public String attributeKey() {
            return attributeKey;
        }

        @Override public String toString() {
            return tagName + "[" + attributeKey + "]";
        }
    }

    /** An attribute that was added or changed by an enforced attribute rule. */
    public static class AddedAttribute {
        private final String tagName;
        private final String attributeKey;
        private final @Nullable String value;

        AddedAttribute(String tagName, String attributeKey, @Nullable String value) {
            this.tagName = tagName;
            this.attributeKey = attributeKey;
            this.value = value;
        }

        /** Get the name of the element the added attribute is on. */
        public String tagName() {
            return tagName;
        }

        /** Get the key of the added attribute. */
        public String attributeKey() {
            return attributeKey;
        }

        /** Get the enforced value of the added attribute. */
        public @Nullable String value() {
            return value;
        }

        @Override public String toString() {
            return tagName + "[" + attributeKey + "=" + value + "]";
        }
    }
}
