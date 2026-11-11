package org.jsoup.safety;

import org.jsoup.Jsoup;
import org.jsoup.TextUtil;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.parser.StreamParser;
import org.jsoup.parser.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 Tests for cleaning during the parse, via {@link Parser#cleaner(Cleaner)} (issue #2284).
 */
public class ParserCleaningTest {
    @Test void cleansDuringParse() {
        String html = "<div><p onclick='x'>One <script>bad()</script><b>two</b></p><table><tr><td>3</td></tr></table></div>";
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        Document clean = Jsoup.parse(html, "", parser);

        String expected = TextUtil.stripNewlines(Jsoup.clean(html, Safelist.basic()));
        assertEquals(expected, TextUtil.stripNewlines(clean.body().html()));
        // the unwrapped table content is retained (text cells), matching the two-pass Cleaner
        assertEquals("<p>One <b>two</b></p>3", TextUtil.stripNewlines(clean.body().html()));
    }

    @Test void cleaningDuringParseMatchesCleanerForCorpus() {
        String[] inputs = {
            "<div><p class=foo><a href='http://evil.com'>Hello <b id=bar>there</b>!</a></div>",
            "<div><p><a href='javascript:sendAllMoney()'>Dodgy</a> <A HREF='HTTP://nice.com'>Nice</a></p><blockquote>Hello</blockquote>",
            "<h1>Head</h1><table><tr><td>One<td>Two</td></tr></table>",
            "<p>Hello<!-- no --></p>",
            "<?import namespace=\"xss\"><p>Hello</p>",
            "<a href='http://example.com/' rel='nofollow'>OK</a>",
            "<svg><script> a < b </script></svg>",
            "<div style=\"font-family: 'Calibri'\">Will (not) fail</div>",
            "<p>5 is &lt; 6.</p>",
            "<ul><li>One<li>Two</ul>",
        };
        Safelist[] safelists = {Safelist.basic(), Safelist.relaxed(), Safelist.basicWithImages(), Safelist.simpleText(), Safelist.relaxed5()};

        for (Safelist safelist : safelists) {
            Parser parser = Parser.htmlParser().cleaner(new Cleaner(safelist));
            for (String input : inputs) {
                String expected = TextUtil.stripNewlines(Jsoup.clean(input, safelist));
                Document parsed = Jsoup.parse(input, "", parser);
                assertEquals(expected, TextUtil.stripNewlines(parsed.body().html()), input);
            }
        }
    }

    @Test void cleaningErrorsAreCollectedDuringParse() {
        CleaningErrors errors = new CleaningErrors();
        Parser parser = Parser.htmlParser()
            .cleaner(new Cleaner(Safelist.basic()))
            .cleaningErrors(errors);

        Jsoup.parse("<p onclick=x>One <script>bad</script><b>two</b></p>", "", parser);

        assertEquals(1, errors.droppedTags().size());
        assertEquals("script", errors.droppedTags().get(0).tagName());
        assertEquals(1, errors.droppedAttributes().size());
        assertEquals("onclick", errors.droppedAttributes().get(0).attributeKey());

        // errors are cleared at the start of each parse
        Jsoup.parse("<p>Clean</p>", "", parser);
        assertTrue(errors.isEmpty());
    }

    @Test void cleansFullDocumentAndStripsHead() {
        String html = "<!doctype html><html lang=en><head><title>T</title><script>x</script></head><body class=b><p onclick=x>Hi</p></body></html>";
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        Document doc = Jsoup.parse(html, "", parser);

        assertEquals("<html><head></head><body><p>Hi</p></body></html>", TextUtil.stripNewlines(doc.html()));
    }

    @Test void cleansXmlSyntax() {
        String xml = "<root><p onclick=x>One<script>bad</script><b>two</b></p></root>";
        Parser parser = Parser.xmlParser().cleaner(new Cleaner(Safelist.relaxed()));
        Document doc = Jsoup.parse(xml, "", parser);

        assertEquals("<root><p>Onebad<b>two</b></p></root>", doc.html());
    }

    @Test void cleansFromReader() throws IOException {
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        Document doc = parser.parseInput(new StringReader("<p onclick=x>Hi <b>there</b></p>"), "");
        assertEquals("<p>Hi <b>there</b></p>", TextUtil.stripNewlines(doc.body().html()));
    }

    @Test void cleanerIsCopiedToNewInstances() {
        Cleaner cleaner = new Cleaner(Safelist.basic());
        Parser parser = Parser.htmlParser().cleaner(cleaner);
        Parser copy = parser.newInstance();
        assertSame(cleaner, copy.cleaner()); // the cleaner is safe to share

        Document doc = Jsoup.parse("<p onclick=x>Hi</p>", "", copy);
        assertEquals("<p>Hi</p>", TextUtil.stripNewlines(doc.body().html()));
    }

    @Test void cleanerCanBeRemoved() {
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        parser.cleaner(null);
        assertNull(parser.cleaner());

        Document doc = Jsoup.parse("<p onclick=x>Hi</p>", "", parser);
        assertTrue(doc.body().html().contains("onclick"));
    }

    @Test void cleanElementIsHonoredForFragments() {
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        Element frag = Jsoup.parseBodyFragment("<p onclick=x>Hi</p>").body().child(0);
        // a fragment parsed with the cleaning parser retains safe content only
        List<org.jsoup.nodes.Node> nodes = parser.parseFragmentInput("<p onclick=x>Hi <b>there</b></p>", frag, "");
        assertEquals(1, nodes.size());
        assertEquals("<p>Hi <b>there</b></p>", TextUtil.stripNewlines(nodes.get(0).outerHtml()));
    }

    @Test void streamsOnlySafeElements() throws IOException {
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.basic()));
        try (StreamParser streamer = new StreamParser(parser).parse("<div><p>One</p><script>bad</script><p>Two</p></div>", "")) {
            List<String> tags = new ArrayList<>();
            while (streamer.iterator().hasNext()) {
                tags.add(streamer.iterator().next().tagName());
            }
            assertFalse(tags.contains("script"));
            assertTrue(tags.contains("p"));

            streamer.complete();
            assertEquals("<p>One</p><p>Two</p>", TextUtil.stripNewlines(streamer.document().body().html()));
        }
    }

    @Test void cleansNamespacedContent() {
        String html = "<p>Hi <svg viewBox='0 0 10 10'><circle cx=1 cy=2 r=3/><script>alert(1)</script></svg></p>";
        Parser parser = Parser.htmlParser().cleaner(new Cleaner(Safelist.relaxed5()));
        Document doc = Jsoup.parse(html, "", parser);

        Element svg = doc.expectFirst("svg");
        assertEquals(Parser.NamespaceSvg, svg.tag().namespace());
        assertEquals(1, svg.childrenSize());
        assertEquals("circle", svg.child(0).normalName());
        assertNull(doc.selectFirst("script"));
    }

    @Test void rejectsNoscriptInParseClean() {
        // safelist validation of noscript is unchanged
        assertThrows(IllegalArgumentException.class, () -> Safelist.relaxed5().addTags("noscript"));
        assertFalse(Safelist.relaxed5().isSafeTag(new Tag("noscript")));
    }
}
