import re
from itertools import chain

from whoosh.analysis import STOP_WORDS, Analyzer, Filter, LowercaseFilter, PassFilter, RegexTokenizer, StopFilter
from whoosh.qparser import Plugin, RegexTagger, attach, syntax
from whoosh.util.text import rcompile


class IntraWordFilter(Filter):
    is_morph = True

    __inittypes__ = dict(delims=str, splitwords=bool, splitnums=bool, merge=bool)

    def __init__(self, delims="-_'\"()!@#$%^&*[]{}<>\\|;:,./?`~=+", splitwords=True, splitnums=True, merge=False):
        """
        :param delims: a string of delimiter characters.
        :param splitwords: if True, split at case transitions,
            e.g. `PowerShot` -> `Power`, `Shot`
        :param splitnums: if True, split at letter-number transitions,
            e.g. `SD500` -> `SD`, `500`
        :param merge: Whether to merge.
        """

        from whoosh.support.unicode import digits, lowercase, uppercase

        self.delims = re.escape(delims)

        # Expression for text between delimiter characters
        self.between = re.compile("[^%s]+" % (self.delims,), re.UNICODE)
        # Expression for removing "'s" from the end of sub-words
        dispat = "(?<=[%s%s])'[Ss](?=$|[%s])" % (lowercase, uppercase, self.delims)
        self.possessive = re.compile(dispat, re.UNICODE)

        # Expression for finding case and letter-number transitions
        lower2upper = "[%s][%s]" % (lowercase, uppercase)
        letter2digit = "[%s%s][%s]" % (lowercase, uppercase, digits)
        digit2letter = "[%s][%s%s]" % (digits, lowercase, uppercase)
        if splitwords and splitnums:
            splitpat = "(%s|%s|%s)" % (lower2upper, letter2digit, digit2letter)
            self.boundary = re.compile(splitpat, re.UNICODE)
        elif splitwords:
            self.boundary = re.compile(lower2upper, re.UNICODE)
        elif splitnums:
            numpat = "(%s|%s)" % (letter2digit, digit2letter)
            self.boundary = re.compile(numpat, re.UNICODE)

        self.splitting = splitwords or splitnums
        self.merge = merge

    def __eq__(self, other):
        return other and self.__class__ is other.__class__ and self.__dict__ == other.__dict__

    def _split(self, string):
        bound = self.boundary

        # Yields (startchar, endchar) pairs for each indexable substring in
        # the given string, e.g. "WikiWord" -> (0, 4), (4, 8)

        # Whether we're splitting on transitions (case changes, letter -> num,
        # num -> letter, etc.)
        splitting = self.splitting

        # Make a list (dispos, for "dispossessed") of (startchar, endchar)
        # pairs for runs of text between "'s"
        if "'" in string:
            # Split on possessive 's
            dispos = []
            prev = 0
            for match in self.possessive.finditer(string):
                dispos.append((prev, match.start()))
                prev = match.end()
            if prev < len(string):
                dispos.append((prev, len(string)))
        else:
            # Shortcut if there's no apostrophe in the string
            dispos = ((0, len(string)),)

        # For each run between 's
        for sc, ec in dispos:
            # Split on boundary characters
            for part_match in self.between.finditer(string, sc, ec):
                part_start = part_match.start()
                part_end = part_match.end()

                if splitting:
                    # The point to start splitting at
                    prev = part_start
                    # Find transitions (e.g. "iW" or "a0")
                    for bmatch in bound.finditer(string, part_start, part_end):
                        # The point in the middle of the transition
                        pivot = bmatch.start() + 1
                        # Yield from the previous match to the transition
                        # No delimiter here?
                        yield prev, pivot
                        # Make the transition the new starting point
                        prev = pivot

                    # If there's leftover text at the end, yield it too
                    if prev < part_end:
                        yield prev, part_end
                else:
                    # Not splitting on transitions, just yield the part
                    yield part_start, part_end

    def _merge(self, full_text, parts):
        newtext = "".join(item[0] for item in parts)
        newtext = ""
        last_end = 0
        for item in parts:
            text, pos, startchar, endchar = item
            if startchar == last_end + 1:
                newtext += full_text[last_end]
            newtext += text
            last_end = endchar
        newpos = parts[0][1]
        newsc = parts[0][2]  # start char of first item in buffer
        newec = parts[-1][3]  # end char of last item in buffer
        parts.insert(0, (newtext, newpos, newsc, newec))

    def __call__(self, tokens):
        # This filter renumbers tokens as it expands them. New position
        # counter.
        newpos = None
        for t in tokens:
            text = t.text

            # If this is the first token we've seen, use it to set the new
            # position counter
            if newpos is None:
                if t.positions:
                    newpos = t.pos
                else:
                    # Token doesn't have positions, just use 0
                    newpos = 0

            if (text.isalpha() and (text.islower() or text.isupper())) or text.isdigit():
                # Short-circuit the common cases of no delimiters, no case
                # transitions, only digits, etc.
                t.pos = newpos
                yield t
                newpos += 1
            else:
                # Split the token text on delimiters, word and/or number
                # boundaries into a list of (text, pos, startchar, endchar)
                # tuples
                ranges = self._split(text)
                parts = [(text[sc:ec], i + newpos, sc, ec) for i, (sc, ec) in enumerate(ranges)]

                # Did the split yield more than one part?
                if len(parts) > 1:
                    # If the options are set, merge consecutive runs of all-
                    # letters and/or all-numbers.
                    if self.merge:
                        self._merge(text, parts)

                # Yield tokens for the parts
                chars = t.chars
                if chars:
                    base = t.startchar
                for text, pos, startchar, endchar in parts:
                    t.text = text
                    t.pos = pos
                    if t.chars:
                        t.startchar = base + startchar
                        t.endchar = base + endchar
                    yield t

                if parts:
                    # Set the new position counter based on the last part
                    newpos = parts[-1][1] + 1


class VerbatimPhrasePlugin(Plugin):
    """Adds the ability to specify phrase queries inside double quotes."""

    # Didn't use TaggingPlugin because I need to add slop parsing at some
    # point

    # Expression used to find words if a schema isn't available
    wordexpr = rcompile(r"\S+")

    class PhraseNode(syntax.TextNode):
        def __init__(self, text, textstartchar, slop=1):
            syntax.TextNode.__init__(self, text)
            self.textstartchar = textstartchar
            self.slop = slop

        def r(self):
            return "%s %r~%s" % (self.__class__.__name__, self.text, self.slop)

        def apply(self, fn):
            return self.__class__(self.type, [fn(node) for node in self.nodes], slop=self.slop, boost=self.boost)

        def query(self, parser):
            text = self.text
            fieldname = self.fieldname or parser.fieldname

            # We want to process the text of the phrase into "words" (tokens),
            # and also record the startchar and endchar of each word

            sc = self.textstartchar
            if parser.schema and fieldname in parser.schema:
                field = parser.schema[fieldname]
                if field.analyzer:
                    # We have a field with an analyzer, so use it to parse
                    # the phrase into tokens
                    tokens = field.tokenize(text, mode="phrase", chars=True)
                    words = []
                    char_ranges = []
                    for t in tokens:
                        words.append(t.text)
                        char_ranges.append((sc + t.startchar, sc + t.endchar))
                else:
                    # We have a field but it doesn't have a format object,
                    # for some reason (it's self-parsing?), so use process_text
                    # to get the texts (we won't know the start/end chars)
                    words = list(field.process_text(text, mode="phrase"))
                    char_ranges = [(None, None)] * len(words)
            else:
                # We're parsing without a schema, so just use the default
                # regular expression to break the text into words
                words = []
                char_ranges = []
                for match in VerbatimPhrasePlugin.wordexpr.finditer(text):
                    words.append(match.group(0))
                    char_ranges.append((sc + match.start(), sc + match.end()))

            qclass = parser.phraseclass
            q = qclass(fieldname, words, slop=self.slop, boost=self.boost, char_ranges=char_ranges)
            return attach(q, self)

    class PhraseTagger(RegexTagger):
        def create(self, parser, match):
            text = match.group("text")
            textstartchar = match.start("text")
            slopstr = match.group("slop")
            slop = int(slopstr) if slopstr else 1
            return VerbatimPhrasePlugin.PhraseNode(text, textstartchar, slop)

    def __init__(self, expr='"(?P<text>.*?)"(~(?P<slop>[1-9][0-9]*))?'):
        self.expr = expr

    def taggers(self, parser):
        return [(self.PhraseTagger(self.expr), 0)]


class MultiFilter(Filter):
    default_filter = PassFilter()

    def __init__(self, **kwargs):
        self.filters = kwargs

    def __eq__(self, other):
        return other and self.__class__ is other.__class__ and self.filters == other.filters

    def __call__(self, tokens):
        # Only selects on the first token
        try:
            t = next(tokens)
            filter = self.filters.get(t.mode, self.default_filter)
            return filter(chain([t], tokens))
        except StopIteration:
            return tokens


def FancyAnalyzer() -> Analyzer:
    expression = r"\s+"
    stoplist = STOP_WORDS
    minsize = 1
    maxsize = None
    gaps = True
    iwf_i = IntraWordFilter(merge=True)
    iwf_p = PassFilter()
    iwf_q = IntraWordFilter(merge=False)
    iwf = MultiFilter(index=iwf_i, query=iwf_q, phrase=iwf_p)

    return (
        RegexTokenizer(expression=expression, gaps=gaps)
        | iwf
        | LowercaseFilter()
        | StopFilter(stoplist=stoplist, minsize=minsize, maxsize=maxsize)
    )
