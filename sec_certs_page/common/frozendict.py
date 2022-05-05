# Copyright (c) 2012 Santiago Lezica
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from copy import deepcopy


def immutable(self, *args, **kwargs):
    r"""
    Function for not implemented method since the object is immutable
    """

    raise AttributeError(f"'{self.__class__.__name__}' object is read-only")


class frozendict(dict):  # pragma: no cover
    r"""
    A simple immutable dictionary.

    The API is the same as `dict`, without methods that can change the
    immutability. In addition, it supports __hash__().
    """

    __slots__ = ("_hash",)

    @classmethod
    def fromkeys(cls, *args, **kwargs):
        r"""
        Identical to dict.fromkeys().
        """

        return cls(dict.fromkeys(*args, **kwargs))

    def __init__(self, *args, **kwargs):
        pass

    def __hash__(self, *args, **kwargs):
        r"""
        Calculates the hash if all values are hashable, otherwise raises a
        TypeError.
        """

        if self._hash is not None:
            _hash = self._hash
        else:
            try:
                fs = frozenset(self.items())
            except TypeError:
                _hash = -1
            else:
                _hash = hash(fs)

            object.__setattr__(self, "_hash", _hash)

        if _hash == -1:
            raise TypeError("Not all values are hashable.")

        return _hash

    def __repr__(self, *args, **kwargs):
        r"""
        Identical to dict.__repr__().
        """

        body = super().__repr__(*args, **kwargs)
        return f"frozendict({body})"

    def copy(self):
        r"""
        Return the object itself, as it's an immutable.
        """

        return self

    def __copy__(self, *args, **kwargs):
        r"""
        See copy().
        """

        return self.copy()

    def __deepcopy__(self, *args, **kwargs):
        r"""
        As for tuples, if hashable, see copy(); otherwise, it returns a
        deepcopy.
        """

        try:
            hash(self)
        except TypeError:
            tmp = deepcopy(dict(self))

            return self.__class__(tmp)

        return self.__copy__(*args, **kwargs)

    def __reduce__(self, *args, **kwargs):
        r"""
        Support for `pickle`.
        """

        return (self.__class__, (dict(self),))

    def __setitem__(self, key, val, *args, **kwargs):
        raise TypeError(f"'{self.__class__.__name__}' object doesn't support item " "assignment")

    def __delitem__(self, key, *args, **kwargs):
        raise TypeError(f"'{self.__class__.__name__}' object doesn't support item " "deletion")


def frozendict_or(self, other, *args, **kwargs):  # pragma: no cover
    res = {}
    res.update(self)
    res.update(other)

    return self.__class__(res)


def frozendict_reversed(self, *args, **kwargs):  # pragma: no cover
    return reversed(tuple(self))


frozendict.__or__ = frozendict_or  # type: ignore
frozendict.__ior__ = frozendict.__or__  # type: ignore
frozendict.__reversed__ = frozendict_reversed  # type: ignore
frozendict.clear = immutable  # type: ignore
frozendict.pop = immutable  # type: ignore
frozendict.popitem = immutable  # type: ignore
frozendict.setdefault = immutable  # type: ignore
frozendict.update = immutable  # type: ignore
frozendict.__delattr__ = immutable  # type: ignore
frozendict.__setattr__ = immutable  # type: ignore


def frozen_new(e4b37cdf_d78a_4632_bade_6f0579d8efac, *args, **kwargs):  # pragma: no cover
    cls = e4b37cdf_d78a_4632_bade_6f0579d8efac

    has_kwargs = bool(kwargs)
    continue_creation = True

    # check if there's only an argument and it's of the same class
    if len(args) == 1 and not has_kwargs:
        it = args[0]

        # no isinstance, to avoid subclassing problems
        if it.__class__ == frozendict and cls == frozendict:
            self = it
            continue_creation = False

    if continue_creation:
        self = dict.__new__(cls, *args, **kwargs)

        dict.__init__(self, *args, **kwargs)

        # empty singleton - start

        if (self.__class__ == frozendict) and not len(self):
            try:
                self = cls.empty
                continue_creation = False
            except AttributeError:
                cls.empty = self

        # empty singleton - end

        if continue_creation:
            object.__setattr__(self, "_hash", None)

    return self


frozendict.__new__ = frozen_new  # type: ignore
