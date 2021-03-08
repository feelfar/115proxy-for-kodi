# -*- coding: utf-8 -*-
"""

PyHTML
======

Simple HTML generator for Python.


Usage:

Lets create a tag.

>>> t = div()
>>> t
div()


Tags can be rendered by converting to string.

>>> str(t)
'<div></div>'


Printing an object automatically calls str() with that object.
I will keep printing tags in this tutorial for clarity.

>>> print(div())
<div></div>


Parantheses can be omitted if the tag has no content.

>>> print(div)
<div></div>


Some tags are self closing.
>>> print(hr)
<hr/>


You can put some content into the tag.
>>> print(div('content'))
<div>
  content
</div>


You can set attributes of the tag.

>>> print(div(lang='tr', id='content', class_="bar", data_value="foo"))
<div class="bar" data-value="foo" id="content" lang="tr"></div>


Or both:

>>> print(div(lang='tr')('content'))
<div lang="tr">
  content
</div>


Content can be anything which can be converted to string.

If content is a callable, it will be called with a one argument
    that is the context you pass to render() as keyword arguments.

>>> greet = lambda ctx: 'Hello %s' % ctx.get('user', 'guest')
>>> greeting = div(greet)
>>> print(greeting)
<div>
  Hello guest
</div>
>>> print(greeting.render(user='Cenk'))
<div>
  Hello Cenk
</div>


You can give list of items as content.

>>> print(div(nav(), greet, hr))
<div>
  <nav></nav>
  Hello guest
  <hr/>
</div>


You can give give a callable returning a list as content.

>>> items = lambda ctx: [li('a'), li('b')]
>>> print(ul(items))
<ul>
  <li>
    a
  </li>
  <li>
    b
  </li>
</ul>


You can give give a generator as content.

>>> def items(ctx):
...    for i in range(3):
...        yield li(i)
>>> print(ul(items))
<ul>
  <li>
    0
  </li>
  <li>
    1
  </li>
  <li>
    2
  </li>
</ul>


You can nest tags.

>>> print(div(div(p('a paragraph'))))
<div>
  <div>
    <p>
      a paragraph
    </p>
  </div>
</div>


Some tags have sensible defaults.

>>> print(form())
<form method="POST"></form>

>>> print(html())
<!DOCTYPE html>
<html></html>


Full example:

>>> print(html(
...     head(
...         title('Awesome website'),
...         script(src="http://path.to/script.js")
...     ),
...     body(
...         header(
...             img(src='/path/to/logo.png'),
...         ),
...         div(
...             'Content here'
...         ),
...         footer(
...             hr,
...             'Copyright 2012'
...         )
...     )
... ))
<!DOCTYPE html>
<html>
  <head>
    <title>
      Awesome website
    </title>
    <script src="http://path.to/script.js" type="text/javascript"></script>
  </head>
  <body>
    <header>
      <img src="/path/to/logo.png"/>
    </header>
    <div>
      Content here
    </div>
    <footer>
      <hr/>
      Copyright 2012
    </footer>
  </body>
</html>

"""

from __future__ import print_function
import sys
from copy import deepcopy
from types import GeneratorType
import lib.six as six

if sys.version_info[0] >= 3:
    from typing import Dict, List  # noqa

__version__ = '1.3.1'

# The list will be extended by register_all function.
__all__ = 'Tag Block Safe Var SelfClosingTag html script style form'.split()

tags = 'head body title div p h1 h2 h3 h4 h5 h6 u b i s a em strong span '\
       'font del_ ins ul ol li dd dt dl article section nav aside header '\
       'footer audio video deo_video object_ embed param fieldset legend button '\
       'label select datalist option table thead tbody tr th td caption '\
       'blockquote cite q abbr acronym address'

self_closing_tags = 'meta link br hr input_ img'

whitespace_sensitive_tags = 'code samp pre var kbd dfn source textarea'

INDENT = 2


def _escape(text):
    r = (
        ('&', '&amp;'),
        ('<', '&lt;'),
        ('>', '&gt;'),
        ('"', '&quot;'),
        ("'", '&#x27;'), )
    for k, v in r:
        text = text.replace(k, v)
    return text


class TagMeta(type):
    """Type of the Tag. (type(Tag) == TagMeta)
    """

    def __str__(cls):
        """Renders as empty tag."""
        if cls.self_closing:
            return '<%s/>' % cls.__name__
        else:
            return '<%s></%s>' % (cls.__name__, cls.__name__)

    def __repr__(cls):
        return cls.__name__


@six.python_2_unicode_compatible
class Tag(six.with_metaclass(TagMeta, object)):  # type: ignore

    safe = False  # do not escape while rendering
    self_closing = False
    whitespace_sensitive = False
    default_attributes = {}  # type: Dict[str, str]
    doctype = None  # type: str

    def __init__(self, *children, **attributes):
        _safe = attributes.pop('_safe', None)
        if _safe is not None:
            self.safe = _safe

        # Only children or attributes may be set at a time.
        assert ((bool(children) ^ bool(attributes)) or (not children and not attributes))

        if self.self_closing and children:
            raise Exception("Self closing tag can't have children")

        self.children = children

        self.blocks = {}  # type: Dict[str, List[Block]]
        self._set_blocks(children)

        self.attributes = self.default_attributes.copy()
        self.attributes.update(attributes)

    def __call__(self, *children, **options):
        if self.self_closing:
            raise Exception("Self closing tag can't have children")

        _safe = options.pop('_safe', None)
        if _safe is not None:
            self.safe = _safe

        self.children = children
        self._set_blocks(children)
        return self

    def __repr__(self):
        if self.attributes and not self.children:
            return "%s(%s)" % (self.name, self._repr_attributes())
        elif self.children and not self.attributes:
            return "%s(%s)" % (self.name, self._repr_children())
        elif self.attributes and self.children:
            return "%s(%s)(%s)" % (self.name, self._repr_attributes(), self._repr_children())
        else:
            return "%s()" % self.name

    def _repr_attributes(self):
        return ', '.join("%s=%r" % (key, value) for key, value in six.iteritems(self.attributes))

    def _repr_children(self):
        return ', '.join(repr(child) for child in self.children)

    def __str__(self):
        return self.render()

    @property
    def name(self):
        return self.__class__.__name__

    def copy(self):
        return deepcopy(self)

    def render(self, _out=None, _indent=0, **context):
        if _out is None:
            _out = six.StringIO('')

        # Write doctype
        if self.doctype:
            _out.write(' ' * _indent)
            _out.write(self.doctype)
            _out.write('\n')

        # Indent opening tag
        _out.write(' ' * _indent)

        # Open tag
        _out.write('<%s' % self.name)

        self._write_attributes(_out, context)

        if self.self_closing:
            _out.write('/>')
        else:
            # Close opening tag
            _out.write('>')

            if self.children:
                # Newline after opening tag
                if not self.whitespace_sensitive:
                    _out.write('\n')

                # Write content
                self._write_list(self.children, _out, context,
                                 _indent + INDENT)

                if not self.whitespace_sensitive:
                    # Newline after content
                    _out.write('\n')
                    # Indent closing tag
                    _out.write(' ' * _indent)

            # Write closing tag
            _out.write('</%s>' % self.name)

        return _out.getvalue()

    def _write_list(self, l, out, context, indent=0):
        for i, child in enumerate(l):
            # Write newline between items
            if i != 0 and not self.whitespace_sensitive:
                out.write('\n')

            self._write_item(child, out, context, indent)

    def _write_item(self, item, out, context, indent):
        if isinstance(item, Tag):
            item.render(out, indent, **context)
        elif isinstance(item, TagMeta):
            self._write_as_string(item, out, indent, escape=False)
        elif callable(item):
            rv = item(context)
            self._write_item(rv, out, context, indent)
        elif isinstance(item, (GeneratorType, list, tuple)):
            self._write_list(item, out, context, indent)
        else:
            self._write_as_string(item, out, indent)

    def _write_as_string(self, s, out, indent, escape=True):
        if isinstance(s, six.text_type) and not isinstance(out, six.StringIO):
            s = s
        elif s is None:
            s = ''
        elif not isinstance(s, six.string_types):
            s = str(s)

        if escape and not self.safe:
            s = _escape(s)

        # Write content
        if not self.whitespace_sensitive:
            lines = s.splitlines(True)
            for line in lines:
                out.write(' ' * indent)
                out.write(line)
        else:
            out.write(s)

    def _write_attributes(self, out, context):
        for key, value in sorted(self.attributes.items()):
            # Some attribute names such as "class" conflict
            # with reserved keywords in Python. These must
            # be postfixed with underscore by user.
            if key.endswith('_'):
                key = key.rstrip('_')

            # Dash is preffered to underscore in attribute names.
            key = key.replace('_', '-')

            if callable(value):
                value = value(context)

            if isinstance(value, six.text_type) and not isinstance(
                    out, six.StringIO):
                value = value

            if not isinstance(value, six.string_types):
                value = str(value)

            value = _escape(value)

            out.write(' %s="%s"' % (key, value))

    def __setitem__(self, block_name, *children):
        for block in self.blocks[block_name]:
            block(*children)

        self._set_blocks(children, block_name=block_name)

    def _set_blocks(self, children, block_name=None):
        for child in children:
            if isinstance(child, Block):
                if child.block_name == block_name:
                    self.blocks[child.block_name] = [child]
                elif child.block_name not in self.blocks:
                    self.blocks[child.block_name] = []
                self.blocks[child.block_name].append(child)
            elif isinstance(child, Tag):
                for blocks in child.blocks.values():
                    self._set_blocks(blocks, block_name=block_name)


class Block(Tag):
    """List of renderable items."""

    def __init__(self, name):
        super(Block, self).__init__()
        self.block_name = name
        self.children = ()

    def __repr__(self):
        if not self.children:
            return 'Block(%r)' % self.block_name
        else:
            return 'Block(%r)(%s)' % (self.block_name, self._repr_children())

    def render(self, _out=None, _indent=0, **context):
        if _out is None:
            _out = six.StringIO('')

        self._write_list(self.children, _out, context, _indent)
        return _out.getvalue()


class Safe(Block):
    """Helper for wrapping content that do not need escaping."""

    safe = True

    def __init__(self, *children, **options):
        super(Safe, self).__init__(None)
        super(Safe, self).__call__(*children, **options)


def Var(var, default=None):
    """Helper function for printing a variable from context."""
    return lambda ctx: ctx.get(var, default)


class SelfClosingTag(Tag):
    self_closing = True


class WhitespaceSensitiveTag(Tag):
    whitespace_sensitive = True


class html(Tag):
    doctype = '<!DOCTYPE html>'


class script(Tag):
    safe = True
    default_attributes = {'type': 'text/javascript'}


class style(Tag):
    default_attributes = {'type': 'text/css'}


class form(Tag):
    default_attributes = {'method': 'POST'}


_M = sys.modules[__name__]


def register_all(tags, parent):
    for tag in tags.split():
        __all__.append(tag)
        setattr(_M, tag, type(tag, (parent, ), {'name': tag.rstrip('_').replace('_', '-')}))


register_all(tags, Tag)
register_all(self_closing_tags, SelfClosingTag)
register_all(whitespace_sensitive_tags, WhitespaceSensitiveTag)


if __name__ == "__main__":
    import doctest
    doctest.testmod(extraglobs={'print_function': print_function})  # type: ignore
