# Modified from original source, available here:
# http://code.activestate.com/recipes/577624-orderedset/

import collections.abc as collections  # Python 3


class OrderedSet(collections.MutableSet):
    """Set that remembers original insertion order."""

    KEY, PREV, NEXT = range(3)

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]  # sentinel node for doubly linked list
        self.map = {}  # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __contains__(self, key):
        return key in self.map

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)

    def __iter__(self):
        end = self.end
        curr = end[self.NEXT]
        while curr is not end:
            yield curr[self.KEY]
            curr = curr[self.NEXT]

    def __len__(self):
        return len(self.map)

    def __reversed__(self):
        end = self.end
        curr = end[self.PREV]
        while curr is not end:
            yield curr[self.KEY]
            curr = curr[self.PREV]

    def add(self, key):
        if key not in self.map:
            end = self.end
            curr = end[self.PREV]
            curr[self.NEXT] = end[self.PREV] = self.map[key] = [key, curr, end]

    def discard(self, key):
        if key in self.map:
            key, prev, next = self.map.pop(key)
            prev[self.NEXT] = next
            next[self.PREV] = prev

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = next(reversed(self)) if last else next(iter(self))
        self.discard(key)
        return key

    def __del__(self):
        self.clear()  # remove circular references

    def __repr__(self):
        class_name = self.__class__.__name__
        if not self:
            return '{0!s}()'.format(class_name)
        return '{0!s}({1!r})'.format(class_name, list(self))


if __name__ == '__main__':
    print(OrderedSet('abracadaba'))
    print(OrderedSet('simsalabim'))
    x = OrderedSet('abracadaba')
    # doesn't raise "Exception TypeError: TypeError('list indices must be integers, not NoneType',) in ignored"
