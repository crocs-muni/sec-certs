import re

from whoosh.analysis import STOP_WORDS, Analyzer, Filter, LowercaseFilter, MultiFilter, RegexTokenizer, StopFilter


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


def FancyAnalyzer() -> Analyzer:
    expression = r"\s+"
    stoplist = STOP_WORDS
    minsize = 1
    maxsize = None
    gaps = True
    iwf_i = IntraWordFilter(merge=True)
    iwf_q = IntraWordFilter(merge=False)
    iwf = MultiFilter(index=iwf_i, query=iwf_q)

    return (
        RegexTokenizer(expression=expression, gaps=gaps)
        | iwf
        | LowercaseFilter()
        | StopFilter(stoplist=stoplist, minsize=minsize, maxsize=maxsize)
    )
