# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Lark-based bash-subset parser that turns a command line into a list
# ABOUTME: of statements (token lists, subshells, syntax errors) for the shell.

"""
A small Lark grammar and evaluator that tokenises a command line and resolves
its quoting, redirection, command substitution and subshells for the shell in
``honeypot.py``.

The parser produces a list of :class:`Statement` objects -- simple commands and
the compound commands ``for`` / ``if`` / ``while`` / ``until`` / ``case``, brace
groups, subshells and function definitions -- each carrying the operator that
joins it to the previous one (``;`` / ``&&`` / ``||``) and still-unevaluated word
trees. Words are expanded only when a statement is about to run (see
:meth:`BashParser.evaluate`), so the shell can interleave parsing and execution
like a real shell. The control operators a real shell cares about — ``|`` and
the redirection operators — pass through as their own string tokens so the
existing ``CommandParser`` / ``runCommand`` machinery consumes the result
unchanged.

There is a single tokeniser for the whole language: the Lark grammar lexes a
line (or a whole multi-line script) into word trees and control tokens, and the
recursive descent in :meth:`BashParser._parse_list` recognises reserved words
only at a command position to build the compound structure, exactly as a real
shell parses. The one clause the grammar recognises itself is ``case``: its
pattern close is the only ``)`` bash allows without a matching ``(``, and
keeping every paren paired is what makes a line parse in linear time.
Newlines separate statements like ``;`` so a script is parsed directly rather
than line-by-line.

The grammar models the subset of bash that Cowrie emulates: lists separated by
``;`` / newline / ``&&`` / ``||``, pipelines, simple redirections, single/double
quoting, ``$VAR`` / ``${VAR}`` expansion, command substitution (``$(...)`` and
backticks), subshells (``(...)``), the compound commands above, and function
definitions.

Known deviations from standard bash (none are emulated yet):

* A trailing ``&`` is treated as a literal argument, not a background job.
* No word expansions beyond ``$VAR`` / ``${VAR}``: tilde (``~``), brace
  (``{a,b}`` / ``{1..3}``) and ANSI-C quoting (``$'...'``) are passed through
  literally. Arithmetic (``$((1+2))``) runs as a command substitution of a
  subshell, so ``1+2`` is reported as a command not found. The parameter
  expansion operators (``${x:-y}``, ``${#x}``, ``${x/a/b}`` ...) are a syntax
  error.
* Word splitting always uses the default ``IFS`` (space, tab, newline); an
  assigned ``IFS`` is ignored.
* QPot: pathname expansion (globbing of ``*`` / ``?`` / ``[...]``) is done
  here, as bash does it without nullglob, dotglob or extglob, bounded (see
  ``qpot_pathnames``); ``case`` patterns are matched with fnmatch.
* A compound command nested inside ``$(...)`` is not captured (its output is
  empty); command substitution captures simple commands and subshells only.
* ``$@`` / ``$#`` / ``$*`` expand to the positional parameters of the running
  function or script; with none set they are empty (``$#`` is 0). Other
  special parameters (``$!``, ``$$`` ...) other than ``$?`` are kept literally.

Here-documents are lifted out of the input before the grammar sees it, by the
pre-scanner in ``prescan`` (the body of ``<<EOF`` depends on an earlier word,
which a context-free grammar cannot express): each rides on its command as a
:class:`HereDoc` item and is expanded with the command's words.

Incomplete input -- an open quote, ``$(``, ``${`` or backtick, a trailing
backslash, a compound command still missing its closing word, a line ending
in ``|`` / ``&&`` / ``||``, or a here-document body without its delimiter --
comes back as a single trailing :class:`SyntaxError_` with ``incomplete``
set. A shell reading line by line keeps the text and asks for more (the
``> `` prompt); one given the whole text at once reports it the way bash
does at end of file. Any other input the grammar cannot parse surfaces as a
plain syntax error.
"""

from __future__ import annotations

import contextlib
import gc
import os
import re
import signal
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from collections.abc import Awaitable, Iterator

from lark import Lark, Token, Tree
from lark.exceptions import LarkError, UnexpectedCharacters, UnexpectedEOF
from twisted.logger import Logger

from cowrie.core.config import CowrieConfig
from cowrie.shell.parser import Field, HereDocBody
from cowrie.shell.prescan import HereDoc, scan


def qpot_cap_fnmatch_cache() -> None:
    """QPot: fnmatch keeps the last 32768 patterns it compiled, over 100 KB each for a 4 KB pattern,
    and the attacker's case patterns, globs, find -name and apt arguments all go through it: one
    session sending distinct long patterns grew Cowrie by 100 MB per 800 of them, toward the
    container's memory limit. Keep the last 256 (re keeps its own 512)."""
    import fnmatch
    import functools

    compile_pattern = getattr(fnmatch, "_compile_pattern", None)
    uncached = getattr(compile_pattern, "__wrapped__", None)
    if callable(uncached):
        fnmatch._compile_pattern = functools.lru_cache(maxsize=256, typed=True)(uncached)  # type: ignore[attr-defined]


qpot_cap_fnmatch_cache()

# Grammar for the supported bash subset. Whitespace is significant as a word
# separator, so it is matched explicitly rather than ignored: adjacent atoms
# with no whitespace between them form a single word ("a"$x'b' -> one word).
#
# The grammar is a single tokeniser for the whole language: it emits a flat
# stream of word trees, "(...)" and case groups, and control tokens
# (separators, pipes, redirections, newlines). The structure above a simple
# command -- &&/|| lists, pipelines, and the compound commands
# for/if/while/until, brace groups and function definitions -- is recognised
# by the recursive descent in :meth:`BashParser._parse_list`, which reads
# reserved words only at a command position, exactly as a real shell does.
# Keeping one tokeniser means the script-level constructs reuse the same
# quoting, expansion and redirection lexing as a single interactive line.
#
# The grammar is unambiguous: every line has exactly one parse. That is what
# keeps the Earley parse linear in the input size (issue #40597), and
# test_bashparse asserts it with an explicit-ambiguity parse of sample lines.

# >>> tpot shell arithmetic
TPOT_ARITH_MAX_LENGTH = 4096
TPOT_ARITH_MAX_TOKENS = 20000
TPOT_ARITH_MAX_LEVELS = 9
TPOT_ARITH_MAX_DEPTH = 80  # four calls per paren level: the 14 levels of the grammar fit
_ARITH_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ARITH_DIGIT = frozenset("0123456789")
_ARITH_ALNUM = _ARITH_ALPHA | _ARITH_DIGIT
_ARITH_SINGLE = frozenset("=><+-*/%!()&|^~?:,")
_ARITH_NUM, _ARITH_STR, _ARITH_EOS = "num", "str", "eos"
_ARITH_ASSIGN = "op="
TPOT_ASH_ERRORS = {"division by 0": "divide by zero", "exponent less than 0": "exponent less than 0",
                   "expression recursion level exceeded": "expression recursion loop detected",
                   "`:' expected for conditional expression": "malformed ?: operator"}
_ARITH_BINARY = (("|",), ("^",), ("&",), ("==", "!="), ("<", ">", "<=", ">="), ("<<", ">>"), ("+", "-"))


def tpot_arith_wrap(value: int) -> int:
    """T-Pot: a value as 64 bit two's complement, the intmax_t of the shell."""
    return ((value + (1 << 63)) & ((1 << 64) - 1)) - (1 << 63)


def tpot_arith_divide(left: int, right: int, remainder: bool) -> int:
    """T-Pot: C division and remainder (towards zero); right is not 0."""
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        quotient = -quotient
    return tpot_arith_wrap(left - quotient * right if remainder else quotient)


class TpotArithError(Exception):
    """T-Pot: an error of $(( )): the shell's text, the status it ends the list with, and whether ash made it."""

    tpot_arith = True

    def __init__(self, message: str, status: int = 1, ash: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.ash = ash


class TpotArith:
    """T-Pot: $(( )) as a port of evalexp of bash 5 expr.c (tests/fixtures/shell_arith.json) with the ash dialects."""

    def __init__(self, env: dict, style: str = "bash", level: int = 0, budget: list | None = None) -> None:
        self.env = env
        self.style = style
        self.ash = style.startswith("ash")
        self.level = level
        self.budget = budget if budget is not None else [0]
        self.expr = ""
        self.tp = 0
        self.lasttp: int | None = None
        self.curtok = self.lasttok = _ARITH_EOS
        self.tokstr = ""
        self.tokval = 0
        self.assigntok = ""
        self.noeval = 0
        self.depth = 0

    def error(self, message: str) -> None:
        if self.ash:
            raise TpotArithError(TPOT_ASH_ERRORS.get(message, "arithmetic syntax error"), 2, True)
        shown = self.expr.lstrip(" \t")
        token = self.expr[self.lasttp:] if self.lasttp is not None else ""
        raise TpotArithError(f'{shown}: {message} (error token is "{token}")', 1)

    def evaluate(self, expr: str) -> int:
        if len(expr) > TPOT_ARITH_MAX_LENGTH:
            self.expr = expr[:TPOT_ARITH_MAX_LENGTH]
            self.error("expression recursion level exceeded")  # derived: bash has no such limit, a longer one is cut
        self.expr = expr
        if not expr.strip(" \t\n\r"):
            return 0
        self.readtok()
        value = self.expcomma()
        if self.curtok != _ARITH_EOS:
            self.error("`:' expected for conditional expression" if self.ash and self.curtok == ":"
                       else "syntax error in expression")
        return value

    # -- tokens -------------------------------------------------------------

    def streval(self, name: str) -> int:
        value = self.env.get(name)
        if not value:
            return 0
        if self.level >= TPOT_ARITH_MAX_LEVELS:
            self.error("expression recursion level exceeded")
        return TpotArith(self.env, self.style, self.level + 1, self.budget).evaluate(value)

    def strlong(self, text: str) -> int:
        base, index, value, foundbase = 10, 0, 0, False
        if text[0] == "0":
            if len(text) > 1 and text[1] in "xX":
                if self.ash and len(text) == 2:
                    self.error("syntax error")
                base, index = 16, 2
            else:
                base, index = 8, 1
        while index < len(text):
            char = text[index]
            index += 1
            if char == "#":
                if foundbase or self.style == "ash1":
                    self.error("invalid number")
                if value < 2 or value > 64:
                    self.error("invalid arithmetic base")
                base, value, foundbase = value, 0, True
                if index >= len(text) or not (text[index] in _ARITH_ALNUM or text[index] == "@"):
                    self.error("invalid integer constant")
                continue
            if char in _ARITH_DIGIT:
                digit = ord(char) - 48
            elif "a" <= char <= "z":
                digit = ord(char) - 87
            elif "A" <= char <= "Z":
                digit = ord(char) - (55 if base <= 36 else 29)
            elif char == "@":
                digit = 62
            elif char == "_":
                digit = 63
            else:
                break
            if digit >= base:
                self.error("value too great for base")
            value = tpot_arith_wrap(value * base + digit)
        return value

    def readtok(self) -> None:
        expr, size = self.expr, len(self.expr)
        cp = self.tp
        while cp < size and expr[cp] in " \t\n\r":
            cp += 1
        if cp >= size:
            self.lasttok, self.curtok = self.curtok, _ARITH_EOS
            self.tp = size + 1
            return
        char = expr[cp]
        self.lasttp = start = cp
        cp += 1
        self.budget[0] += 1
        if self.budget[0] > TPOT_ARITH_MAX_TOKENS:
            self.error("expression recursion level exceeded")  # derived, not recorded: bounds the work of one call
        if char in _ARITH_ALPHA:
            while cp < size and expr[cp] in _ARITH_ALNUM:
                cp += 1
            if cp < size and expr[cp] == "[" and not self.ash:
                # an element of an array: arrays are not kept, so it reads 0 (an unset one)
                end = tpot_arith_close(expr, cp + 1, "[", "]")
                if end < 0:
                    self.error("bad array subscript")
                cp = end + 1
            self.tokstr = expr[start:cp]
            self.tokval = self.streval(self.tokstr) if self.noeval == 0 else 0
            self.lasttok, self.curtok = self.curtok, _ARITH_STR
            self.tp = cp
            return
        if char in _ARITH_DIGIT:
            while cp < size and (expr[cp] in _ARITH_ALNUM or expr[cp] in "#@"):
                cp += 1
            self.tokstr = expr[start:cp]
            self.tokval = self.strlong(self.tokstr)
            self.lasttok, self.curtok = self.curtok, _ARITH_NUM
            self.tp = cp
            return
        token = char
        follow = expr[cp] if cp < size else ""
        if char in "=!<>" and follow == "=":
            token, cp = char + "=", cp + 1
        elif char in "<>" and follow == char:
            cp += 1
            if cp < size and expr[cp] == "=":
                self.assigntok, token, cp = char + char, _ARITH_ASSIGN, cp + 1
            else:
                token = char + char
        elif char in "&|" and follow == char:
            token, cp = char + char, cp + 1
        elif char == "*" and follow == "*":
            token, cp = "**", cp + 1
        elif char in "+-" and follow == char and self.curtok == _ARITH_STR:
            token, cp = char + char + "post", cp + 1
        elif char in "+-" and follow == char and self.incdec_pre(cp + 1):
            token, cp = char + char + "pre", cp + 1
        elif follow == "=" and char in "*/%+-&^|":
            self.assigntok, token, cp = char, _ARITH_ASSIGN, cp + 1
        elif char not in _ARITH_SINGLE:
            if self.curtok == _ARITH_EOS or self.curtok in _ARITH_SINGLE:
                self.error("syntax error: operand expected")
            self.error("syntax error: invalid arithmetic operator")
        self.lasttok, self.curtok = self.curtok, token
        self.tp = cp

    def incdec_pre(self, after: int) -> bool:
        """Whether ++ or -- here is a pre-increment: BusyBox before 1.33 reads every one as such, 1.33 where an
        operand does not end, bash and later BusyBox where a name follows."""
        if self.style == "ash1":
            return True
        if self.style == "ash2":
            return self.curtok not in (_ARITH_NUM, ")")
        return after < len(self.expr) and self.expr[after] in _ARITH_ALPHA

    # -- grammar, lowest precedence first -----------------------------------

    def enter(self) -> None:
        self.depth += 1
        if self.depth > TPOT_ARITH_MAX_DEPTH:
            self.error("expression recursion level exceeded")

    def expcomma(self) -> int:
        value = self.expassign()
        while self.curtok == ",":
            self.readtok()
            value = self.expassign()
        return value

    def operate(self, operator: str, left: int, right: int) -> int:
        if operator == "+":
            return tpot_arith_wrap(left + right)
        if operator == "-":
            return tpot_arith_wrap(left - right)
        if operator == "*":
            return tpot_arith_wrap(left * right)
        if operator in "/%":
            return tpot_arith_divide(left, right, operator == "%")
        if operator == "<<":
            return tpot_arith_wrap(left << (right & 63))
        if operator == ">>":
            return left >> (right & 63)
        if operator == "&":
            return left & right
        if operator == "^":
            return left ^ right
        return left | right

    def expassign(self) -> int:
        self.enter()
        value = self.expcond()
        if self.curtok in ("=", _ARITH_ASSIGN):
            special = self.curtok == _ARITH_ASSIGN
            if self.lasttok != _ARITH_STR:
                self.error("attempted assignment to non-variable")
            operator, lvalue, name = self.assigntok, value, self.tokstr
            if not name:
                self.error("syntax error in variable assignment")
            self.readtok()
            value = self.expassign()
            if special:
                if operator in ("/", "%") and value == 0:
                    if self.noeval == 0:
                        self.error("division by 0")
                    value = 1
                value = self.operate(operator, lvalue, value)
            if self.noeval == 0:
                self.env[name] = str(value)
        self.depth -= 1
        return value

    def expcond(self) -> int:
        cval = value = self.explor()
        if self.curtok == "?":
            self.readtok()
            if self.curtok in (_ARITH_EOS, ":"):
                self.error("expression expected")
            skip = cval == 0
            self.noeval += skip
            first = self.expcond() if self.ash else self.expcomma()
            self.noeval -= skip
            if self.curtok != ":":
                self.error("`:' expected for conditional expression")
            self.readtok()
            if self.curtok == _ARITH_EOS:
                self.error("expression expected")
            skip = bool(cval)
            self.noeval += skip
            second = self.expcond()
            self.noeval -= skip
            value = first if cval else second
            self.lasttok = "?"
        return value

    def explor(self) -> int:
        value = self.expland()
        while self.curtok == "||":
            self.readtok()
            skip = value != 0 and not self.ash
            self.noeval += skip
            right = self.expland()
            self.noeval -= skip
            value = int(bool(value or right))
            self.lasttok = _ARITH_NUM
        return value

    def expland(self) -> int:
        value = self.expbin(0)
        while self.curtok == "&&":
            self.readtok()
            skip = value == 0 and not self.ash
            self.noeval += skip
            right = self.expbin(0)
            self.noeval -= skip
            value = int(bool(value and right))
            self.lasttok = _ARITH_NUM
        return value

    def expbin(self, index: int) -> int:
        if index == len(_ARITH_BINARY):
            return self.expmuldiv()
        value = self.expbin(index + 1)
        while self.curtok in _ARITH_BINARY[index]:
            operator = self.curtok
            self.readtok()
            right = self.expbin(index + 1)
            if operator == "==":
                value = int(value == right)
            elif operator == "!=":
                value = int(value != right)
            elif operator == "<":
                value = int(value < right)
            elif operator == ">":
                value = int(value > right)
            elif operator == "<=":
                value = int(value <= right)
            elif operator == ">=":
                value = int(value >= right)
            else:
                value = self.operate(operator, value, right)
            self.lasttok = _ARITH_NUM
        return value

    def expmuldiv(self) -> int:
        value = self.exppower()
        while self.curtok in ("*", "/", "%"):
            operator = self.curtok
            after = self.tp
            self.readtok()
            right = self.exppower()
            if operator != "*" and right == 0:
                if self.noeval:
                    right = 1
                else:
                    while after < len(self.expr) and self.expr[after] in " \t":
                        after += 1
                    self.lasttp = after
                    self.error("division by 0")
            value = self.operate(operator, value, right)
            self.lasttok = _ARITH_NUM
        return value

    def exppower(self) -> int:
        self.enter()
        value = self.exp1()
        while self.curtok == "**":
            self.readtok()
            exponent = self.exppower()
            self.lasttok = _ARITH_NUM
            if exponent == 0:
                self.depth -= 1
                return 1
            if exponent < 0:
                self.error("exponent less than 0")
            result, base = 1, value
            while exponent:
                if exponent & 1:
                    result = tpot_arith_wrap(result * base)
                base = tpot_arith_wrap(base * base)
                exponent >>= 1
            value = result
        self.depth -= 1
        return value

    def exp1(self) -> int:
        self.enter()
        token = self.curtok
        if token in ("!", "~", "-", "+"):
            self.readtok()
            operand = self.exp1()
            value = {"!": int(operand == 0), "~": ~operand, "-": tpot_arith_wrap(-operand), "+": operand}[token]
            self.lasttok = _ARITH_NUM
        else:
            value = self.exp0()
        self.depth -= 1
        return value

    def bind(self, name: str, value: int) -> None:
        if self.noeval == 0:
            self.env[name] = str(value)

    def exp0(self) -> int:
        token = self.curtok
        if token in ("++pre", "--pre"):
            self.lasttok = token
            self.readtok()
            if self.curtok != _ARITH_STR:
                self.error("identifier expected after pre-increment or pre-decrement")
            value = tpot_arith_wrap(self.tokval + (1 if token == "++pre" else -1))
            self.bind(self.tokstr, value)
            self.curtok = _ARITH_NUM
            self.readtok()
        elif token == "(":
            self.enter()
            self.readtok()
            value = self.expcomma()
            if self.curtok != ")":
                self.error("missing `)'")
            self.depth -= 1
            self.readtok()
        elif token in (_ARITH_NUM, _ARITH_STR):
            value = self.tokval
            if token == _ARITH_STR:
                saved = (self.curtok, self.lasttok, self.tp, self.lasttp, self.tokval, self.tokstr, self.noeval)
                self.noeval = 1
                self.readtok()
                follow = self.curtok
                if follow in ("++post", "--post"):
                    self.tokstr, self.noeval, self.lasttok = saved[5], saved[6], _ARITH_STR
                    self.bind(self.tokstr, tpot_arith_wrap(value + (1 if follow == "++post" else -1)))
                    self.curtok = _ARITH_NUM
                else:
                    (self.curtok, self.lasttok, self.tp, self.lasttp, self.tokval, self.tokstr, self.noeval) = saved
            self.readtok()
        else:
            self.error("syntax error: operand expected")
        return value


def tpot_arith(expr: str, env: dict, style: str = "bash") -> str:
    """T-Pot: the value of an expression as text; env holds the variables and takes the assignments."""
    evaluator = TpotArith(env, style)
    try:
        return str(evaluator.evaluate(expr))
    except RecursionError:
        evaluator.error("expression recursion level exceeded")
    return ""


def tpot_arith_style() -> str:
    """T-Pot: bash, ash1 (BusyBox before 1.33), ash2 (before 1.36), ash3 or msh; the ash thresholds lie between
    the recorded releases (1.25, 1.33, 1.36), derived, not recorded."""
    style = CowrieConfig.get("shell", "not_found_style", fallback="bash")
    if style == "ash":
        found = re.search(r"BusyBox v1\.(\d+)", CowrieConfig.get("shell", "text_banner", fallback=""))
        minor = int(found.group(1)) if found else 36
        return "ash1" if minor < 33 else "ash2" if minor < 36 else "ash3"
    return style


def tpot_arith_close(text: str, start: int, opener: str, closer: str) -> int:
    """T-Pot: the index of the closer that ends the group opened before start, -1 when there is none."""
    depth = 1
    for index in range(start, len(text)):
        if text[index] == opener:
            depth += 1
        elif text[index] == closer:
            depth -= 1
            if depth == 0:
                return index
    return -1


async def tpot_arith_expand(context, text: str, level: int = 0) -> str:
    """T-Pot: $name, ${name}, $?, $$, $( ), backticks and $(( )) inside; ${x:-d}, $# and $@ are not expanded."""
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char == "`":
            end = text.find("`", index + 1)
            if end < 0:
                out.append(text[index:])
                break
            out.append(await context.command_substitution(text[index + 1:end]))
            index = end + 1
            continue
        if char != "$":
            out.append(char)
            index += 1
            continue
        if text.startswith("$((", index):
            end = tpot_arith_close(text, index + 2, "(", ")")
            if end > 0 and text[end - 1] == ")" and level < TPOT_ARITH_MAX_LEVELS:
                out.append(await tpot_arith_value(context, text[index + 3:end - 1], level + 1))
                index = end + 1
                continue
        if text.startswith("$(", index):
            end = tpot_arith_close(text, index + 2, "(", ")")
            if end > 0:
                out.append(await context.command_substitution(text[index + 2:end]))
                index = end + 1
                continue
        if text.startswith("${", index):
            end = text.find("}", index + 2)
            if end > 0:
                value = context.get_variable(text[index + 2:end])
                out.append(value if value is not None else "")
                index = end + 1
                continue
        found = re.compile(r"\$[_a-zA-Z0-9]+").match(text, index)
        if found:
            value = context.get_variable(found.group(0)[1:])
            out.append(value if value is not None else "")
            index = found.end()
        elif text.startswith("$?", index):
            out.append(context.get_status())
            index += 2
        elif text.startswith("$$", index):
            out.append(tpot_shell_pid(context))
            index += 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


async def tpot_arith_value(context, body: str, level: int = 0) -> str:
    """T-Pot: the value of $((body)); raises TpotArithError (msh has no arithmetic: a syntax error, status 255)."""
    style = tpot_arith_style()
    if style == "msh":
        raise TpotArithError("syntax error", 255)
    text = await tpot_arith_expand(context, body, level)
    if style == "bash":
        text = text.replace('"', "")
    return tpot_arith(text, context.environ, style)


def tpot_arith_grammar(nesting: int = 14) -> tuple:
    """T-Pot: the regexes of the $(( )) terminal and of the $( that is no $(( ), groups inside up to `nesting` deep."""
    body = r"[^()]*"
    for _ in range(nesting):
        body = r"(?:[^()]|\(" + body + r"\))*"
    return r"\$\(\(" + body + r"\)\)", r"\$\((?!\(" + body + r"\)\))"
# <<< tpot shell arithmetic

_GRAMMAR = r"""
// A line is contents (words, groups, comments) and operators in any order.
// Whitespace is REQUIRED between two contents, so a run of atoms with no
// spaces is a single word (a"b"$c -> one word) while operators stay
// self-delimiting (echo a|b is three tokens); it is optional around an
// operator. Two left-recursive sequences -- _after_content and _after_op,
// named for what they end in -- give every whitespace run exactly one place
// to attach. (Left recursion: Earley handles it in linear time where a
// right-recursive list is quadratic.)
start: _WS? _seq?
_seq: (_after_content | _after_op) _WS?
_after_content: _content | _after_content _WS _arg | _after_op _WS? _content
// After another word, "esac" is an ordinary argument ("echo esac"). In command
// position it only ever closes a case (LITERAL never matches it), so a case
// body without a final ";;" cannot absorb the next "esac" as a command.
_arg: _content | esac_arg
esac_arg: ESAC -> word
_after_op: _op | _after_content _WS? _op | _after_op _WS? _op
_content: subshell | word | _funcdef | case_clause | _COMMENT
// A function definition's "()" is one token, so "f()", "f ()" and "f ( )"
// all read the same way, and the body may follow it directly ("f(){ ...; }").
_funcdef: word _WS? FUNC_PARENS _content?
FUNC_PARENS: /\([ \t]*\)/
_op: SEP | PIPE | AMP | IO_REDIR | REDIR | NEWLINE

// "(" only ever opens a group and ")" only ever closes one: a "(...)" is a
// subshell, a "(" that never closes is a syntax error, and the one ")" bash
// allows without a matching "(" -- the close of a case pattern like "x86*)"
// -- is recognised by the case_clause rule below. Keeping the parens out of
// _op matters for parse cost: Earley builds every reading of the input, and
// if either could stand alone, every "(...)" and "$(...)" could close at any
// later ")" on the line (issue #40597). A subshell has at least one command:
// "( )" is a syntax error in bash, and an empty "()" is FUNC_PARENS.
subshell: LPAR body RPAR
body: _WS? _seq

// "case WORD in [(]PAT[|PAT]...) BODY ;; ... esac". The keywords are only
// keywords here: elsewhere "case", "in" and "esac" lex as ordinary words.
case_clause: CASE _WS word _WS IN _blank* case_item* ESAC
case_item: (LPAR _WS?)? case_patterns _WS? RPAR start (DSEMI _blank*)?
case_patterns: word (_WS? PIPE _WS? word)*
_blank: _WS | NEWLINE
CASE: /case(?=\s)/
IN: /in(?=\s)/
ESAC: /esac(?![^\s;&|<>()])/

// A "#" starts a comment only at a word start (see _COMMENT), so a LITERAL
// never begins with one; inside a word ("a#b", "''#x") it is ordinary text.
word: _atom (_atom | HASH_LITERAL)*
_atom: sq | dq | arith | cmdsub | backtick | dollar_brace | dollar_var | ESC | BARE_DOLLAR | LITERAL
HASH_LITERAL: /#[^ \t\r\n|&;<>()$`'"\\]*/

// An explicit "$(" terminal: BARE_DOLLAR never matches before a "(".
cmdsub: CMDSUB_OPEN start ")"
CMDSUB_OPEN: /@CMDSUB@/
// T-Pot: $((...)) is a term of its own; a $( that starts a group of its own is a substitution
arith: ARITH
ARITH: /@ARITH@/

backtick: "`" _bq_atom* "`"
_bq_atom: dollar_var | dollar_brace | BQ_LITERAL
BQ_LITERAL: /[^`]+/

dq: "\"" _dq_part* "\""
_dq_part: arith | cmdsub | backtick | dollar_brace | dollar_var | DQ_ESC | DQ_TEXT | BARE_DOLLAR
DQ_TEXT: /[^"$`\\]+/
// A lone backslash is literal only where it escapes nothing, so "\\" has
// exactly one reading: one escaped backslash, never two literal ones. The
// backslash comes last in each class: Lark reads \\" as an escaped quote and
// would drop it from the class.
DQ_ESC: /\\[$`"\\]/ | /\\(?![$`"\\])/

sq: SQ
SQ: /'[^']*'/

dollar_brace: "${" BRACE_NAME "}"
BRACE_NAME: /[_a-zA-Z][_a-zA-Z0-9]*\[(?:[0-9]{1,9}|[@*])\]|[_a-zA-Z0-9]+|[?@$#!*]/

dollar_var: DOLLAR_NAME | DOLLAR_SPECIAL
DOLLAR_NAME: /\$[_a-zA-Z0-9]+/
DOLLAR_SPECIAL: /\$[?@$#!*]/

ESC: /\\./

// A single-character operator never matches where a longer one starts
// (";;", "&&", "||", "&>"), so each operator has exactly one reading.
DSEMI: ";;"
SEP: "&&" | "||" | /;(?!;)/
PIPE: /\|(?!\|)/
AMP: /&(?![&>])/
// A redirection with a file descriptor directly attached to it ("2>", "2>&",
// "1>>"): one token, so the digit is a file descriptor, not an argument (a
// LITERAL never matches digits directly before "<" or ">"). A digit separated
// by whitespace ("2 >") stays an ordinary word, which is how bash tells the
// two apart. The here-document operators "<<" and "<<-" and the here-string
// "<<<" are tokens of their own, longest first, and "<" / "<<" never match
// where a longer one starts, so each has exactly one reading. The body of a
// here-document is not in the input the grammar sees: the pre-scanner lifted
// it out (see prescan.py), leaving the operator and its delimiter word.
IO_REDIR: /\d+(?:>>|>&|>|<<<|<<-|<<(?![<-])|<(?!<))/
REDIR: />>|>&|&>>|&>|>(?![>&])|<<<|<<-|<<(?![<-])|<(?!<)/

LPAR: "("
RPAR: ")"
// A newline separates statements like ";" (so a multi-line script is parsed
// directly); a backslash-newline is a line continuation and counts as
// whitespace (see _WS below).
NEWLINE: /\r?\n/

// A "$" that does not start an expansion: never where DOLLAR_NAME,
// DOLLAR_SPECIAL, "${" or "$(" would match, so a "$x" has one reading.
BARE_DOLLAR: /\$(?![_a-zA-Z0-9{(?@$#!*])/
// Not a "#" first (that is a comment), and not digits directly before a
// redirection operator (that is an IO_REDIR file descriptor, "2>&1").
LITERAL: /(?!#|\d+[<>]|esac(?=[ \t\r\n|&;<>()]|$))[^ \t\r\n|&;<>()$`'"\\]+/

// A "#" at a word start begins a comment.
_COMMENT: /#[^\r\n]*/

// Inline whitespace and line continuations only; a bare newline is NEWLINE.
_WS: /([ \t]|\\\r?\n)+/

// Second start rule: the body of a here-document with an unquoted delimiter.
// It reads like the inside of double quotes -- parameter and command
// substitution, no quoting -- except that a backslash escapes only $ ` \
// and a newline (a line continuation); before anything else it is literal.
heredoc_body: _hd_part*
_hd_part: arith | cmdsub | backtick | dollar_brace | dollar_var | HD_ESC | HD_TEXT | BARE_DOLLAR
HD_TEXT: /[^$`\\]+/
HD_ESC: /\\[$`\\]/ | /\\\r?\n/ | /\\(?![$`\\\r\n])/
"""

_ARITH_TERMINAL, _CMDSUB_TERMINAL = tpot_arith_grammar()
_GRAMMAR = _GRAMMAR.replace("@ARITH@", _ARITH_TERMINAL).replace("@CMDSUB@", _CMDSUB_TERMINAL)
_parser = Lark(
    _GRAMMAR,
    start=["start", "heredoc_body"],
    parser="earley",
    lexer="dynamic",
    propagate_positions=True,
)


def max_input_size() -> int:
    """Maximum size of shell input fed to the parser in one call
    ([shell] max_input_size). The Earley parse cost grows superlinearly with
    input size, so unbounded attacker-controlled input (e.g. an HTML error
    page downloaded in place of a payload and run with ``sh x``) could block
    the reactor for hours and exhaust memory."""
    return CowrieConfig.getint("shell", "max_input_size", fallback=16384)


def max_heredoc_size() -> int:
    """Maximum characters kept of one here-document body ([shell]
    max_heredoc_size). A body is attacker data that never reaches the Earley
    parser unexpanded (an unquoted body larger than max_input_size is used
    literally), so this is a memory cap only: lines beyond it are dropped
    while the delimiter is still awaited, and the input is still logged."""
    return CowrieConfig.getint("shell", "max_heredoc_size", fallback=1048576)


def gc_collect_threshold() -> int:
    """Input length in characters that triggers post-parse garbage collection.

    Lark's Earley parser builds cyclic intermediate structures. CPython's
    reference counting cannot reclaim those structures promptly, so collect
    after larger inputs instead of allowing a busy honeypot to accumulate
    them until a later generation-two collection.
    """
    return CowrieConfig.getint("shell", "gc_collect_threshold", fallback=512)


class ParseTimeoutError(Exception):
    """Raised when a shell parse exceeds ``parse_timeout_seconds``."""


def parse_timeout_seconds() -> float:
    """Maximum wall-clock time for one shell parse; zero disables the limit."""
    return CowrieConfig.getfloat("shell", "parse_timeout_seconds", fallback=10.0)


_HAS_PARSE_ALARM = all(
    hasattr(signal, name)
    for name in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
)


def _raise_parse_timeout(signum: int, frame: object) -> None:
    raise ParseTimeoutError


@contextlib.contextmanager
def _parse_alarm(seconds: float) -> Iterator[None]:
    """Apply a POSIX wall-clock limit without disturbing an embedding app.

    Signals are process-global and Python only permits changing their handlers
    in the main thread. Cowrie uses the alarm only when SIGALRM has its default
    handler and no real-time alarm is already pending; otherwise the caller's
    signal handling takes precedence and parsing proceeds normally.
    """
    if (
        seconds <= 0
        or not _HAS_PARSE_ALARM
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    if signal.getsignal(signal.SIGALRM) is not signal.SIG_DFL:
        yield
        return
    delay, interval = signal.getitimer(signal.ITIMER_REAL)
    if delay or interval:
        yield
        return

    previous_handler = signal.signal(signal.SIGALRM, _raise_parse_timeout)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)


# >>> tpot shell pid
def tpot_shell_pid(context) -> str:
    """T-Pot: the PID of the login shell of the session, the one ps, top and /proc/self show: the one tpot_session of
    the patched base.py drew for the session (tpot_login_pid), else the shell of the ps list, else the one after the
    session's server process."""
    protocol = getattr(context, "protocol", None)
    shell = getattr(protocol, "tpot_login_pid", None)
    if not isinstance(shell, int):
        try:
            from cowrie.commands.base import tpot_session

            shell = tpot_session(protocol, str(getattr(getattr(protocol, "user", None), "username", "root")))["shell"]
        except Exception:  # noqa: BLE001 - without base.py the PID of the ps list
            shell = None
    if isinstance(shell, int):
        return str(shell)
    server = getattr(getattr(protocol, "user", None), "server", None)
    shells = [p["PID"] for p in (getattr(server, "process", None) or [])
              if isinstance(p, dict) and isinstance(p.get("PID"), int)
              and str(p.get("TTY") or "").startswith(("pts/", "tty")) and "getty" not in str(p.get("COMMAND") or "")]
    if shells:
        return str(shells[-1])
    pid = getattr(protocol, "tpot_session_pid", None)
    if not isinstance(pid, int):
        pid = 4000 + int.from_bytes(os.urandom(2), "big") % 4000
        try:
            protocol.tpot_session_pid = pid
        except Exception:  # noqa: BLE001 - a protocol that takes no attribute keeps no PID
            pass
    return str(pid + 1)
# <<< tpot shell pid


class ShellContext(Protocol):
    """What the evaluator needs from the live shell to evaluate words."""

    def get_variable(self, name: str) -> str | None:
        """Return the value of a shell variable, or None if unset."""
        ...

    def get_status(self) -> str:
        """Return ``$?`` -- the last command's exit status, as a string."""
        ...

    def command_substitution(self, source: str) -> Awaitable[str]:
        """Execute ``source``; the awaitable completes with its captured stdout
        (trailing newlines stripped) once every command in it has finished."""
        ...


@dataclass
class Command:
    """A simple command, structure only.

    ``items`` keeps the ordered word trees (still unevaluated) interleaved with
    the redirection operator strings (``>``, ``2>`` ...) and any here-document
    (a :class:`HereDoc`, standing for its ``<<WORD`` operator and delimiter).
    Words are expanded against the live shell by :meth:`BashParser.evaluate`
    only when the command is about to run, so a same-line ``x=hi; echo $x``
    sees the assignment. ``op`` is the operator that joins this statement to
    the previous one (``None`` / ``;`` / ``&&`` / ``||``); ``line`` is the
    source the word trees point into, and ``lineno`` the 1-based line of that
    source it starts on.
    """

    items: list[str | Tree | HereDoc] = field(default_factory=list)
    line: str = ""
    op: str | None = None
    lineno: int = 0


@dataclass
class Pipeline:
    """``cmd | cmd ...``: two or more stages, each any kind of command (a simple
    command, a ``(...)`` or ``{ ...; }`` group, a loop ...), as in a real
    shell. ``op`` joins the pipeline to the previous statement; the stages
    themselves carry no join operator.
    """

    stages: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class Subshell:
    """A ``(...)`` group, holding its parsed (still unevaluated) inner statements.

    Cowrie does not emulate a subshell's isolated environment, so the caller
    runs these statements in order with the surrounding line. ``op`` joins this
    group to the previous statement.
    """

    statements: list[Statement] = field(default_factory=list)
    op: str | None = None
    redirections: Command | None = None


@dataclass
class BraceGroup:
    """A ``{ ...; }`` command group: its statements run in the current shell."""

    statements: list[Statement] = field(default_factory=list)
    op: str | None = None
    redirections: Command | None = None


@dataclass
class ForClause:
    """``for VAR in WORDS; do BODY; done``.

    ``items`` is a :class:`Command` whose words are the (unevaluated) ``in``
    list, expanded against the live shell when the loop runs.
    """

    var: str = ""
    items: Command | None = None
    body: list[Statement] = field(default_factory=list)
    op: str | None = None
    redirections: Command | None = None


@dataclass
class IfClause:
    """``if COND; then BODY; [elif COND; then BODY;]* [else BODY;] fi``.

    ``branches`` pairs each condition statement-list with its body; ``else_body``
    is the optional trailing ``else`` arm.
    """

    branches: list[tuple[list[Statement], list[Statement]]] = field(
        default_factory=list
    )
    else_body: list[Statement] | None = None
    op: str | None = None
    redirections: Command | None = None


@dataclass
class WhileClause:
    """``while COND; do BODY; done`` (or ``until`` when ``until`` is True)."""

    condition: list[Statement] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    until: bool = False
    op: str | None = None
    redirections: Command | None = None


@dataclass
class CaseClause:
    """``case WORD in PATTERN[|PATTERN]) BODY ;; ... esac``.

    ``word`` is a :class:`Command` carrying the (unevaluated) word to match;
    ``items`` pairs each list of raw glob patterns with its body.
    """

    word: Command | None = None
    items: list[tuple[list[str], list[Statement]]] = field(default_factory=list)
    op: str | None = None
    redirections: Command | None = None


@dataclass
class FunctionDef:
    """``name() { BODY; }`` -- registers ``name`` for later invocation."""

    name: str = ""
    body: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class SyntaxError_:
    """A bash-style syntax error to report verbatim.

    TODO: the trailing underscore avoids shadowing the builtin SyntaxError.
    Consider renaming to ParseError for clarity (touches honeypot.py and the
    tests).
    """

    token: str
    # The 1-based line of the parsed input the error is on, and that line's
    # text, which a non-interactive bash quotes after the message.
    lineno: int = 0
    source: str = ""
    # The input ended before the construct did. ``opener`` names what is
    # still open: the closing quote, backtick, ``)`` or ``}`` bash reports in
    # "unexpected EOF while looking for matching `X'", ``\\`` for a trailing
    # backslash, ``heredoc`` for a body without its delimiter (``heredocs``
    # lists them, for the warning), or empty for a compound command or
    # operator still waiting for more words ("unexpected end of file").
    incomplete: bool = False
    opener: str = ""
    heredocs: list[HereDoc] = field(default_factory=list)


class SourceText(str):
    """The stripped input the parser's trees point into, when the pre-scanner
    cut here-document bodies out of it. A plain str otherwise: this subclass
    remembers the original text and the cuts, so a span of a substitution or
    subshell can be sliced from the original with its bodies intact (see
    :meth:`BashParser._slice`)."""

    original: str
    cuts: list[tuple[int, int]]

    def __new__(cls, stripped: str, original: str, cuts: list[tuple[int, int]]) -> Self:
        text = super().__new__(cls, stripped)
        text.original = original
        text.cuts = cuts
        return text

    def to_original(self, pos: int) -> int:
        """The position in the original text of ``pos`` in the stripped one."""
        return pos + sum(removed for at, removed in self.cuts if at <= pos)


Statement = (
    Command
    | Pipeline
    | Subshell
    | BraceGroup
    | ForClause
    | IfClause
    | WhileClause
    | CaseClause
    | FunctionDef
    | SyntaxError_
)

# The compound commands a redirection can follow ("(...) > f", "done 2>&1"),
# carrying it in their ``redirections`` field.
REDIRECTABLE = (Subshell, BraceGroup, ForClause, IfClause, WhileClause, CaseClause)

# Reserved words recognised only at a command position (the start of a
# statement). Anywhere else they are ordinary arguments, so ``echo done`` still
# prints "done", exactly as in bash.
_RESERVED = frozenset(
    {
        "for",
        "in",
        "do",
        "done",
        "if",
        "then",
        "elif",
        "else",
        "fi",
        "while",
        "until",
        "case",
        "esac",
        "function",
        "{",
        "}",
    }
)

# Reserved words that only ever close a construct: at the start of a statement
# that is not the one closing the construct being parsed, each is a syntax
# error, never a command name.
_CLOSERS = frozenset({"then", "elif", "else", "fi", "do", "done", "esac", "}"})

# Tokens that end a statement, and those that end one pipeline stage.
_STATEMENT_END = frozenset({"SEP", "NEWLINE"})
_STAGE_END = _STATEMENT_END | {"PIPE"}

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A word whose leading literal is NAME= is an assignment.
_ASSIGNMENT_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Builtins whose NAME=value arguments are assignments, so not split.
_DECLARATION_BUILTINS = frozenset({"declare", "export", "local", "readonly", "typeset"})
# The characters an unquoted expansion splits on: bash's default IFS.
_IFS_WHITESPACE = " \t\n"
# The special parameters a ``$x`` / ``${x}`` reference can name.
_SPECIAL_PARAMS = frozenset("?@$#!*")

_UNQUOTED_EXPANSIONS = frozenset({"dollar_var", "dollar_brace", "cmdsub", "backtick", "arith"})


class _Cursor:
    """A forward cursor over the grammar's flat child stream."""

    def __init__(self, tokens: list[Tree | Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self, ahead: int = 0) -> Tree | Token | None:
        index = self.pos + ahead
        return self.tokens[index] if 0 <= index < len(self.tokens) else None

    def next(self) -> Tree | Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token



def qpot_subscript(context, name: str) -> str:
    """QPot: ${NAME[INDEX]} of a shell that keeps no arrays: a set variable is element 0 (and all of
    [@] and [*]), BASH_VERSINFO the parts of BASH_VERSION and MACHTYPE, as bash sets it."""
    base, _, index = name[:-1].partition("[")
    if base == "BASH_VERSINFO":
        version = context.get_variable("BASH_VERSION") or ""
        found = re.match(r"([0-9]+)\.([0-9]+)\.([0-9]+)\(([0-9]+)\)-([a-z]+)", version)
        items = list(found.groups()) + [context.get_variable("MACHTYPE") or ""] if found else []
    else:
        value = context.get_variable(base)
        items = [value] if value is not None else []
    if index in ("@", "*"):
        return " ".join(items)
    position = int(index)
    return items[position] if position < len(items) else ""


class BashParser:
    """Parse a command line into a list of statements for the shell to run."""

    _log = Logger()

    def __init__(self, context: ShellContext) -> None:
        self.context = context
        # Per-parse state: the number to add to every 1-based line of the
        # text being parsed (its first line in the shell's input), and the
        # here-documents the pre-scanner lifted out of it, by the position
        # of their "<<" in the stripped text.
        self._line_offset = 0
        self._heredocs: dict[int, HereDoc] = {}

    # -- public API ---------------------------------------------------------

    def parse(self, text: str, *, first_line: int = 1) -> list[Statement]:
        """
        Parse ``text`` into ordered statements. Raises nothing for input the
        grammar rejects: it returns a single :class:`SyntaxError_` with an
        empty token so the caller can emit the generic message, matching the
        previous "unexpected end of file" fallback. Input that merely ends
        too early comes back with a trailing :class:`SyntaxError_` whose
        ``incomplete`` flag is set (see the module docstring). ``first_line``
        is the line number of the text's first line, so a shell fed line by
        line can number its errors from the start of its input.
        """
        self._line_offset = first_line - 1
        scanned = scan(text, max_heredoc=max_heredoc_size())
        if scanned.incomplete in ('"', "'", "`", ")", "}"):
            return [
                SyntaxError_(
                    token="",
                    lineno=scanned.incomplete_line + self._line_offset,
                    incomplete=True,
                    opener=scanned.incomplete,
                )
            ]
        if scanned.incomplete == "(":
            # bash reports an open "(" group like any unfinished compound.
            return [
                SyntaxError_(token="", lineno=self._end_line(text), incomplete=True)
            ]
        if scanned.truncated:
            self._log.info(
                "here-document body truncated to {limit} characters",
                limit=max_heredoc_size(),
            )
        line: str = scanned.stripped
        if scanned.cuts:
            line = SourceText(scanned.stripped, text, scanned.cuts)
        self._heredocs = scanned.heredocs
        try:
            tree = self._lark_parse(line, "start")
        except UnexpectedCharacters as error:
            return [
                SyntaxError_(
                    token=self._unexpected_char(line, error),
                    lineno=error.line + self._line_offset,
                )
            ]
        except UnexpectedEOF:
            # The grammar ran out of input mid-construct (a case item with no
            # esac after it): the backstop for anything the descent below
            # does not see.
            return [
                SyntaxError_(token="", lineno=self._end_line(line), incomplete=True)
            ]
        except (LarkError, ParseTimeoutError):
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        if CowrieConfig.get("shell", "not_found_style", fallback="bash") != "bash":
            # QPot: ash and msh keep no arrays: a ${NAME[INDEX]} fails the whole line (BusyBox 1.37: "bad
            #   substitution", status 2, nothing of the line run)
            for token in tree.scan_values(lambda v: isinstance(v, Token) and v.type == "BRACE_NAME" and "[" in v):
                return [SyntaxError_(token="", lineno=self._node_line(token))]
        statements = self._split_statements(line, tree)
        if statements and isinstance(statements[-1], SyntaxError_):
            return statements
        if scanned.incomplete in ("heredoc", "\\"):
            # A here-document body runs to the end of the input, or the last
            # line continues onto one not yet read: the statements stand, and
            # a line-fed shell reads on while a whole-text one runs them.
            statements.append(
                SyntaxError_(
                    token="",
                    lineno=self._end_line(line),
                    incomplete=True,
                    opener=scanned.incomplete,
                    heredocs=[h for h in self._heredocs.values() if not h.terminated],
                )
            )
        return statements

    def _lark_parse(self, text: str, start: str) -> Tree:
        """Run the grammar from ``start`` over ``text`` under the parse time
        limit, collecting the Earley garbage afterwards for larger input.
        Raises the Lark error or :class:`ParseTimeoutError`."""
        timed_out = False
        try:
            with _parse_alarm(parse_timeout_seconds()):
                return _parser.parse(text, start=start)
        except ParseTimeoutError:
            timed_out = True
            self._log.warn(
                "Shell parse exceeded {timeout}s (input: {length} characters)",
                timeout=parse_timeout_seconds(),
                length=len(text),
            )
            raise
        finally:
            if timed_out or len(text) >= gc_collect_threshold():
                gc.collect()

    def _end_line(self, line: str) -> int:
        """The line bash reports an unexpected end of input on: the one after
        the last."""
        return len(line.rstrip("\n").split("\n")) + 1 + self._line_offset

    def _node_line(self, node: Tree | Token | None) -> int:
        """The 1-based source line a grammar node starts on, or 0."""
        if isinstance(node, Token):
            return node.line + self._line_offset if node.line else 0
        if isinstance(node, Tree) and not node.meta.empty:
            return node.meta.line + self._line_offset
        return 0

    @staticmethod
    def _unexpected_char(line: str, error: UnexpectedCharacters) -> str:
        """The token bash names for input the grammar rejects outright: a
        ")", ";;" or "esac" with nothing to close. Anything else gets the
        generic "unexpected end of file"."""
        rest = line[error.pos_in_stream :]
        for token in (";;", ")"):
            if rest.startswith(token):
                return token
        if re.match(r"esac(?=[ \t\r\n|&;<>()]|$)", rest):
            return "esac"
        return ""

    # -- statement splitting ------------------------------------------------

    def _split_statements(self, line: str, tree: Tree) -> list[Statement]:
        """Recursive-descent parse of the flat token stream into statements."""
        cursor = _Cursor(list(tree.children))
        return self._parse_list(line, cursor, stop=frozenset())

    @staticmethod
    def _token_type(node: Tree | Token | None) -> str | None:
        return node.type if isinstance(node, Token) else None

    def _is_separator(self, node: Tree | Token | None) -> bool:
        return self._token_type(node) in ("SEP", "NEWLINE")

    def _separator_op(self, node: Tree | Token) -> str:
        """The join operator a separator implies: && / || keep their meaning;
        ``;``, a newline and ``&`` all sequence without gating."""
        if self._token_type(node) == "SEP":
            assert isinstance(node, Token)
            return str(node.value)
        return ";"  # NEWLINE

    def _word_literal(self, node: Tree | Token | None) -> str | None:
        """Return the text of a word that is a single unquoted literal atom, else
        None. Keywords are recognised only through this, so a quoted or expanded
        word (``'for'``, ``$kw``) is never treated as reserved."""
        if not isinstance(node, Tree) or node.data != "word":
            return None
        if len(node.children) != 1:
            return None
        atom = node.children[0]
        if isinstance(atom, Token) and atom.type == "LITERAL":
            return str(atom.value)
        return None

    def _keyword(self, node: Tree | Token | None) -> str | None:
        text = self._word_literal(node)
        return text if text in _RESERVED else None

    def _parse_list(
        self, line: str, cursor: _Cursor, stop: frozenset[str]
    ) -> list[Statement]:
        """Parse statements separated by ``;`` / newline / ``&&`` / ``||`` until a
        reserved stop word or the end of input."""
        statements: list[Statement] = []
        pending_op: str | None = None
        seen = False
        # Index of the first statement on the current input line: bash rejects
        # a line with a syntax error as a whole, but has run the lines before.
        line_start = 0

        while True:
            # Consume the separators between statements, tracking the operator
            # that will join the next statement to the previous one.
            while self._is_separator(cursor.peek()):
                separator = cursor.next()
                if self._token_type(separator) == "NEWLINE":
                    line_start = len(statements)
                value = self._separator_op(separator)
                if value in ("&&", "||"):
                    if not seen:
                        # A leading && / || is a bash syntax error.
                        statements.append(
                            SyntaxError_(token=value, lineno=self._node_line(separator))
                        )
                        return statements
                    pending_op = value
                elif pending_op not in ("&&", "||"):
                    pending_op = ";"

            node = cursor.peek()
            if node is None:
                if seen and pending_op in ("&&", "||"):
                    # The input ends after && / ||: bash reads on for the
                    # command the operator needs.
                    statements.append(
                        SyntaxError_(
                            token="", lineno=self._end_line(line), incomplete=True
                        )
                    )
                break
            keyword = self._keyword(node)
            if keyword in stop:
                break
            if keyword in _CLOSERS:
                del statements[line_start:]
                statements.append(
                    SyntaxError_(token=keyword, lineno=self._node_line(node))
                )
                return statements

            statement = self._parse_statement(
                line, cursor, pending_op if seen else None
            )
            statements.append(statement)
            seen = True
            pending_op = None
            if isinstance(statement, SyntaxError_):
                if statement.incomplete:
                    # bash reports an unexpected end of file after the
                    # last line.
                    statement.lineno = self._end_line(line)
                elif not statement.lineno:
                    # The token found, or, for a `newline' with the input
                    # run out, the line that ended.
                    statement.lineno = (
                        self._node_line(cursor.peek())
                        or self._node_line(cursor.peek(-1))
                        or self._end_line(line)
                    )
                return statements

        return statements

    def _parse_statement(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        """One statement: a command, or a pipeline of commands joined by ``|``.

        A newline may follow a ``|`` (bash keeps reading the pipeline on the
        next line); a ``|`` with no command on either side is a syntax error.
        """
        if self._token_type(cursor.peek()) == "PIPE":
            return SyntaxError_(token="|")
        stages = [self._parse_command(line, cursor, op)]
        while self._token_type(cursor.peek()) == "PIPE":
            if isinstance(stages[-1], SyntaxError_):
                break
            cursor.next()  # "|"
            while self._token_type(cursor.peek()) == "NEWLINE":
                cursor.next()
            node = cursor.peek()
            if node is None:
                # The input ends after the "|": bash reads on for the stage.
                return SyntaxError_(token="", incomplete=True)
            if self._token_type(node) == "PIPE":
                return SyntaxError_(token="|")
            stages.append(self._parse_command(line, cursor, None))
        if len(stages) == 1:
            return stages[0]
        if isinstance(stages[-1], SyntaxError_):
            return stages[-1]
        first = stages[0]
        assert not isinstance(first, SyntaxError_)
        first.op = None  # the join operator belongs to the pipeline
        return Pipeline(stages=stages, op=op)

    def _parse_command(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        """One command: a simple command or a compound command, with any
        redirection that follows a compound (`(...) > f`, `done 2>&1`)
        attached to it so the runtime can apply it to the whole group."""
        statement = self._parse_command_head(line, cursor, op)
        if isinstance(statement, REDIRECTABLE):
            redirections = self._collect_redirections(line, cursor)
            if redirections is not None:
                statement.redirections = redirections
        return statement

    def _parse_command_head(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        node = cursor.peek()

        if isinstance(node, Tree) and node.data == "subshell":
            cursor.next()
            after = cursor.peek()
            if isinstance(after, Tree):
                # A word or another group directly after ")" -- bash reports
                # a syntax error near that token. A redirection ("(a) > f")
                # is a REDIR/IO_REDIR token, not a Tree, and is collected by
                # _parse_command instead.
                if after.data == "subshell":
                    return SyntaxError_(token=self._error_token(line, after))
                return SyntaxError_(token=self._word_source(line, after))
            return Subshell(statements=self._subshell_statements(line, node), op=op)

        if isinstance(node, Tree) and node.data == "case_clause":
            cursor.next()
            return self._case_clause(line, node, op)

        keyword = self._keyword(node)
        if keyword == "for":
            return self._parse_for(line, cursor, op)
        if keyword == "if":
            return self._parse_if(line, cursor, op)
        if keyword in ("while", "until"):
            return self._parse_while(line, cursor, op, until=keyword == "until")
        if keyword == "case":
            # The grammar did not recognise a complete case clause here: with
            # no "esac" anywhere after it the clause is still being written
            # ("case x in"), otherwise something after "case" is misplaced.
            cursor.next()
            if cursor.peek() is not None and not self._esac_ahead(cursor):
                return SyntaxError_(token="", incomplete=True)
            return SyntaxError_(token=self._unexpected(line, cursor))
        if keyword == "{":
            return self._parse_brace_group(line, cursor, op)
        if keyword == "function":
            return self._parse_function_keyword(line, cursor, op)
        if self._looks_like_funcdef(cursor):
            return self._parse_function(line, cursor, op)

        return self._parse_simple(line, cursor, op)

    def _collect_redirections(self, line: str, cursor: _Cursor) -> Command | None:
        """Gather the redirections that follow a compound command as a
        :class:`Command` of operator strings and target words, or None if
        there are none. The runtime evaluates and applies them like a simple
        command's own redirections."""
        items: list[str | Tree | HereDoc] = []
        while self._token_type(cursor.peek()) in ("REDIR", "IO_REDIR"):
            operator = cursor.next()
            assert isinstance(operator, Token)
            target = cursor.peek()
            heredoc = self._heredoc_for(operator)
            if heredoc is not None and isinstance(target, Tree):
                cursor.next()
                items.append(heredoc)
                continue
            items.append(str(operator.value))
            if isinstance(target, Tree) and target.data == "word":
                items.append(cursor.next())
        if not items:
            return None
        return Command(items=items, line=line)

    def _heredoc_for(self, operator: Token) -> HereDoc | None:
        """The here-document a ``<<`` / ``<<-`` operator token (with or
        without a leading fd) introduces, with its fd filled in; None for any
        other redirection, or when the pre-scanner found no delimiter word
        after it (the grammar then reports the syntax error)."""
        value = str(operator.value)
        op = value.lstrip("0123456789")
        if op not in ("<<", "<<-") or operator.start_pos is None:
            return None
        heredoc = self._heredocs.get(operator.start_pos + len(value) - len(op))
        if heredoc is not None:
            heredoc.fd = int(value[: len(value) - len(op)] or 0)
        return heredoc

    def _parse_simple(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        """Gather one simple command up to the next ``|`` or statement end."""
        units: list[Tree | Token] = []
        while True:
            node = cursor.peek()
            if node is None or self._token_type(node) in _STAGE_END:
                break
            # A "(...)" that survived as a unit here is a subshell in the middle
            # of a command -- a bash syntax error reported on the "(" token.
            if isinstance(node, Tree) and node.data == "subshell":
                return SyntaxError_(token=self._error_token(line, node))
            # Likewise a case clause, which bash rejects at the pattern's ")",
            # and a "()" after an argument ("echo f()"), rejected at the "(".
            if isinstance(node, Tree) and node.data == "case_clause":
                return SyntaxError_(token=")")
            if self._token_type(node) == "FUNC_PARENS":
                return SyntaxError_(token="(")
            units.append(cursor.next())
        if units and self._token_type(units[-1]) in ("REDIR", "IO_REDIR"):
            # A redirection with an operator where its target should be:
            # bash names it ("|", ";", "&&" ...), or `newline'.
            if isinstance(node, Token) and node.type != "NEWLINE":
                return SyntaxError_(token=str(node.value))
            return SyntaxError_(token="newline")
        return self._make_command(line, units, op)

    def _make_command(
        self, line: str, units: list[Tree | Token], op: str | None
    ) -> Statement:
        # A redirection operator must be followed by a target word. A redirect at
        # the end of a statement, or directly before another operator, is a bash
        # syntax error (e.g. `echo >` reports the unexpected token `newline').
        # Keep the structure; words are evaluated later by evaluate(). An
        # operator token (PIPE / AMP / REDIR / IO_REDIR) is a fixed string,
        # except "<<WORD", which the pre-scanner's HereDoc stands in for.
        items: list[str | Tree | HereDoc] = []
        skip = False
        for i, unit in enumerate(units):
            if skip:
                skip = False
                continue
            if isinstance(unit, Token) and unit.type in ("REDIR", "IO_REDIR"):
                target = units[i + 1] if i + 1 < len(units) else None
                if target is None:
                    return SyntaxError_(token="newline")
                if isinstance(target, Token):
                    return SyntaxError_(token=target.value)
                heredoc = self._heredoc_for(unit)
                if heredoc is not None:
                    items.append(heredoc)
                    skip = True
                    continue
            items.append(unit.value if isinstance(unit, Token) else unit)
        return Command(items=items, line=line, op=op, lineno=self._node_line(units[0]))

    # -- compound commands --------------------------------------------------

    def _parse_for(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        cursor.next()  # "for"
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # NAME

        words: list[Tree] = []
        if self._keyword(cursor.peek()) == "in":
            cursor.next()  # "in"
            while True:
                node = cursor.peek()
                if node is None or self._is_separator(node):
                    break
                if self._keyword(node) == "do":
                    break
                if isinstance(node, Tree) and node.data == "word":
                    cursor.next()
                    words.append(node)
                    continue
                break

        self._skip_separators(cursor)
        if self._keyword(cursor.peek()) != "do":
            return self._unexpected_error(line, cursor)
        cursor.next()  # "do"
        body = self._parse_list(line, cursor, stop=frozenset({"done"}))
        error = self._expect(cursor, "done")
        if error is not None:
            return error
        items = Command(items=list(words), line=line)
        return ForClause(var=name, items=items, body=body, op=op)

    def _parse_if(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        cursor.next()  # "if"
        branches: list[tuple[list[Statement], list[Statement]]] = []
        while True:
            condition = self._parse_list(line, cursor, stop=frozenset({"then"}))
            error = self._expect(cursor, "then")
            if error is not None:
                return error
            body = self._parse_list(
                line, cursor, stop=frozenset({"elif", "else", "fi"})
            )
            branches.append((condition, body))
            if self._keyword(cursor.peek()) == "elif":
                cursor.next()
                continue
            break

        else_body: list[Statement] | None = None
        if self._keyword(cursor.peek()) == "else":
            cursor.next()
            else_body = self._parse_list(line, cursor, stop=frozenset({"fi"}))

        error = self._expect(cursor, "fi")
        if error is not None:
            return error
        return IfClause(branches=branches, else_body=else_body, op=op)

    def _parse_while(
        self, line: str, cursor: _Cursor, op: str | None, until: bool
    ) -> Statement:
        cursor.next()  # "while" / "until"
        condition = self._parse_list(line, cursor, stop=frozenset({"do"}))
        error = self._expect(cursor, "do")
        if error is not None:
            return error
        body = self._parse_list(line, cursor, stop=frozenset({"done"}))
        error = self._expect(cursor, "done")
        if error is not None:
            return error
        return WhileClause(condition=condition, body=body, until=until, op=op)

    def _case_clause(self, line: str, tree: Tree, op: str | None) -> Statement:
        """Build a :class:`CaseClause` from the grammar's ``case_clause`` tree."""
        word: Tree | None = None
        items: list[tuple[list[str], list[Statement]]] = []
        for child in tree.children:
            if not isinstance(child, Tree):
                continue  # the case / in / esac keywords
            if child.data == "word":
                word = child
            elif child.data == "case_item":
                items.append(self._case_item(line, child))
        assert word is not None
        return CaseClause(word=Command(items=[word], line=line), items=items, op=op)

    def _case_item(self, line: str, item: Tree) -> tuple[list[str], list[Statement]]:
        """The raw pattern strings and parsed body of one ``pat[|pat]*) body ;;``."""
        patterns: list[str] = []
        body: list[Statement] = []
        for child in item.children:
            if not isinstance(child, Tree):
                continue  # "(", ")" and ";;"
            if child.data == "case_patterns":
                patterns = [
                    self._word_source(line, node)
                    for node in child.children
                    if isinstance(node, Tree) and node.data == "word"
                ]
            elif child.data == "start":
                body = self._split_statements(line, child)
        return patterns, body

    def _parse_brace_group(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        cursor.next()  # "{"
        body = self._parse_list(line, cursor, stop=frozenset({"}"}))
        error = self._expect(cursor, "}")
        if error is not None:
            return error
        return BraceGroup(statements=body, op=op)

    def _looks_like_funcdef(self, cursor: _Cursor) -> bool:
        """Detect ``name ()`` at command position."""
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return False
        return self._token_type(cursor.peek(1)) == "FUNC_PARENS"

    def _parse_function(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        name = self._word_literal(cursor.next())
        assert name is not None
        self._consume_empty_parens(cursor)
        return self._finish_function(line, cursor, name, op)

    def _parse_function_keyword(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        cursor.next()  # "function"
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # NAME
        self._consume_empty_parens(cursor)
        return self._finish_function(line, cursor, name, op)

    def _consume_empty_parens(self, cursor: _Cursor) -> None:
        if self._token_type(cursor.peek()) == "FUNC_PARENS":
            cursor.next()

    def _finish_function(
        self, line: str, cursor: _Cursor, name: str, op: str | None
    ) -> Statement:
        self._skip_separators(cursor)
        if self._keyword(cursor.peek()) != "{":
            return self._unexpected_error(line, cursor)
        group = self._parse_brace_group(line, cursor, None)
        if isinstance(group, SyntaxError_):
            return group
        assert isinstance(group, BraceGroup)
        return FunctionDef(name=name, body=group.statements, op=op)

    # -- parser helpers -----------------------------------------------------

    def _skip_separators(self, cursor: _Cursor) -> None:
        while self._is_separator(cursor.peek()):
            cursor.next()

    def _expect(self, cursor: _Cursor, keyword: str) -> Statement | None:
        if self._keyword(cursor.peek()) != keyword:
            return self._unexpected_error("", cursor)
        cursor.next()
        return None

    def _unexpected_error(self, line: str, cursor: _Cursor) -> SyntaxError_:
        """The error for a construct that needed another word here: a
        syntax error naming the token found, or, with the input run out, an
        incomplete marker (bash reads on: `for i` and `f() {` wait for more,
        `for` alone does not -- its callers report that themselves)."""
        if cursor.peek() is None:
            return SyntaxError_(token="", incomplete=True)
        return SyntaxError_(token=self._unexpected(line, cursor))

    def _esac_ahead(self, cursor: _Cursor) -> bool:
        """Whether an ``esac`` is still to come: the grammar only lexes one
        as ESAC (bare, or an ``esac_arg`` word), never as a LITERAL."""
        for node in cursor.tokens[cursor.pos :]:
            if isinstance(node, Token) and node.type == "ESAC":
                return True
            if (
                isinstance(node, Tree)
                and node.data == "word"
                and any(
                    isinstance(child, Token) and child.type == "ESAC"
                    for child in node.children
                )
            ):
                return True
        return False

    def _unexpected(self, line: str, cursor: _Cursor) -> str:
        node = cursor.peek()
        if node is None or self._token_type(node) == "NEWLINE":
            return "newline"
        if isinstance(node, Token):
            return str(node.value)
        if node.data == "word":
            return self._word_source(line, node) or "newline"
        return "newline"

    def _word_source(self, line: str, word: Tree) -> str:
        """The raw source text of a word, for keywords and case patterns."""
        if not line or word.meta.empty:
            literal = self._word_literal(word)
            return literal if literal is not None else ""
        return self._slice(line, word.meta.start_pos, word.meta.end_pos)

    @staticmethod
    def _slice(line: str, start: int, end: int) -> str:
        """``line[start:end]`` in the text the trees point into -- taken from
        the original input, here-document bodies included, when the parser
        worked on a stripped copy (see :class:`SourceText`), so a ``$(cat
        <<EOF ...)`` re-parses with its body."""
        if isinstance(line, SourceText):
            return line.original[line.to_original(start) : line.to_original(end)]
        return line[start:end]

    # -- word evaluation ----------------------------------------------------

    async def evaluate(self, command: Command, *, split: bool = True) -> list[str]:
        """Expand a command's words against the live context, now.

        Operator strings pass through; each word tree is evaluated against the
        current shell (variables, command substitution) into its fields. An
        unquoted expansion splits on whitespace and vanishes when empty, as in
        bash. Leading assignments, ``NAME=value`` arguments of declaration
        builtins (``export`` ...) and redirection targets stay one field, as
        does every word when ``split`` is false (a ``case`` word). A command
        substitution suspends the expansion until its subshell finishes, as
        bash blocks on the substitution pipe; substitutions therefore run left
        to right, each to completion before the next. A here-document, and a
        here-string's word with a newline appended, become a
        :class:`HereDocBody` token carrying the fd it feeds.
        """
        tokens: list[str] = []
        leading = True  # still in the NAME=value words before the command
        declaration = False
        redirect_target = False
        here_string_fd: int | None = None  # a "<<<" awaiting its word
        # QPot: one bound for the pathname expansion of all the command's words, so a line of many
        #   patterns cannot hold the reactor for one bound per word
        qpot_budget = [self.QPOT_GLOB_SCAN, self.QPOT_GLOB_BYTES]
        for item in command.items:
            if isinstance(item, HereDoc):
                tokens.append(await self._eval_heredoc(item))
                continue
            if isinstance(item, str):
                op = item.lstrip("0123456789")
                if op == "<<<":
                    here_string_fd = int(item[: len(item) - len(op)] or 0)
                else:
                    tokens.append(item)
                redirect_target = "<" in item or ">" in item
                continue
            assignment = self._is_assignment(item)
            whole = (
                not split
                or redirect_target
                or (assignment and (leading or declaration))
            )
            redirect_target = False
            fields = await self._eval_word(command.line, item, split=not whole, qpot_budget=qpot_budget)
            if here_string_fd is not None:
                tokens.append(HereDocBody("".join(fields) + "\n", fd=here_string_fd))
                here_string_fd = None
                continue
            if leading and not assignment and fields:
                leading = False
                declaration = fields[0] in _DECLARATION_BUILTINS
            tokens.extend(Field(value) for value in fields)
        return tokens

    async def _eval_heredoc(self, heredoc: HereDoc) -> HereDocBody:
        """The body a here-document feeds its command: literal under a quoted
        delimiter, otherwise expanded like the inside of double quotes (a
        body past max_input_size is kept literal rather than parsed)."""
        text = heredoc.body
        if heredoc.expand and len(text) <= max_input_size():
            text = await self._expand_heredoc(text)
        elif heredoc.expand:
            self._log.info(
                "here-document body of {length} characters left unexpanded",
                length=len(text),
            )
        return HereDocBody(text, fd=heredoc.fd)

    async def _expand_heredoc(self, text: str) -> str:
        """Parameter and command substitution over a here-document body, by
        the grammar's ``heredoc_body`` rule. A backslash is removed before
        ``$``, `````, ``\\`` and a newline (a line continuation) and kept
        before anything else."""
        try:
            tree = self._lark_parse(text, "heredoc_body")
        except (LarkError, ParseTimeoutError):
            # An unbalanced "$(" in the body: bash would report it, Cowrie
            # feeds the body as written.
            return text
        parts: list[str] = []
        for part in tree.children:
            if isinstance(part, Token):
                if part.type == "HD_ESC":
                    escaped = str(part.value)[1:]
                    if escaped in ("$", "`", "\\"):
                        parts.append(escaped)
                    elif escaped.endswith("\n"):
                        pass
                    else:
                        parts.append(str(part.value))
                else:  # HD_TEXT, BARE_DOLLAR
                    parts.append(str(part.value))
            elif part.data == "dollar_var" or part.data == "dollar_brace":
                parts.append(self._expand_embedded(part))
            elif part.data == "arith":
                parts.append(await tpot_arith_value(self.context, str(part.children[0])[3:-2]))
            elif part.data == "cmdsub":
                parts.append(
                    await self.context.command_substitution(
                        self._group_source(text, part)
                    )
                )
            elif part.data == "backtick":
                parts.append(
                    await self.context.command_substitution(
                        self._backtick_source(text, part)
                    )
                )
        return "".join(parts)

    @staticmethod
    def _is_assignment(word: Tree) -> bool:
        """Whether a word is NAME=value: its first atom is a literal NAME=."""
        first = word.children[0] if word.children else None
        return (
            isinstance(first, Token)
            and first.type == "LITERAL"
            and _ASSIGNMENT_PREFIX.match(first) is not None
        )

    async def _eval_word(self, line: str, word: Tree, *, split: bool, qpot_budget: list[int] | None = None) -> list[str]:
        """Evaluate a word to its fields.

        Literal and quoted text joins the field it is in; an unquoted
        expansion's result is split on whitespace when ``split`` is set. A
        word made only of empty unquoted expansions yields no field at all,
        like ``echo $unset`` or ``$(true)``, while a quoted empty string
        (``""``) is a field. A ``"$@"`` ends a field at each boundary between
        positional parameters; where the word stays one field, those
        boundaries become spaces, as in ``x="$@"``.
        """
        pieces: list[tuple[str, bool] | None] = []
        # QPot: whether each piece's text may hold pattern characters (unquoted text and unquoted
        #   expansions; quoted and backslash-escaped text never does), for pathname expansion
        qpot_globbing: list[bool] = []
        for atom in word.children:
            if isinstance(atom, Tree) and atom.data == "dq":
                segments = await self._eval_dquoted(line, atom)
                if not segments:
                    # A "$@" with no positional parameters: no text at all,
                    # like an empty unquoted expansion.
                    pieces.append(("", True))
                    qpot_globbing.append(False)
                for i, segment in enumerate(segments):
                    if i:
                        pieces.append(None)
                        qpot_globbing.append(False)
                    pieces.append((segment, False))
                    qpot_globbing.append(False)
                continue
            unquoted = isinstance(atom, Tree) and atom.data in _UNQUOTED_EXPANSIONS
            pieces.append((await self._eval_atom(line, atom), unquoted))
            qpot_globbing.append(unquoted or (isinstance(atom, Token) and atom.type in ("LITERAL", "HASH_LITERAL")))
        if not split:
            if all(piece is not None and piece[1] and not piece[0] for piece in pieces):
                return []
            return ["".join(" " if piece is None else piece[0] for piece in pieces)]
        fields = self._split_fields(pieces)
        if not any(qpot_globbing):
            return fields
        # QPot: pathname expansion (bash's, without nullglob or dotglob): Cowrie left it to each command
        #   and almost none did it, so `cat /etc/cron.d/*` or `cat /home/*/.bash_history` answered
        #   "No such file or directory" right after ls had listed the files
        masked = self.qpot_split_masked(pieces, qpot_globbing)
        if [text for text, _ in masked] != fields:
            return fields
        expanded: list[str] = []
        for text, mask in masked:
            expanded.extend(self.qpot_pathnames(text, mask, qpot_budget))
        return expanded

    # QPot: the bounds of pathname expansion for one command: directory entries looked at, and bytes of
    #   names it expands to (the 64 KiB a typed line may hold: what follows, the command and its log,
    #   costs Cowrie more per byte than the walk); past either a word stays as typed
    QPOT_GLOB_SCAN = 50000
    QPOT_GLOB_BYTES = 65536
    # QPot: the POSIX classes of a bracket expression, as ranges fnmatch knows (C locale)
    QPOT_GLOB_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z",
                         "lower": "a-z", "xdigit": "0-9A-Fa-f", "space": " \t\n\r\f\v", "blank": " \t"}

    @staticmethod
    def qpot_split_masked(pieces: list[tuple[str, bool] | None], globbing: list[bool]) -> list[tuple[str, str]]:
        """_split_fields's fields, each with a mask of its characters: "1" where a pattern character
        there is active (unquoted), "0" where it is literal."""
        fields: list[tuple[str, str]] = []
        current, mask, started = "", "", False
        for piece, active in zip(pieces, globbing):
            if piece is None:
                fields.append((current, mask))
                current, mask, started = "", "", False
                continue
            text, unquoted = piece
            flag = "1" if active else "0"
            if not unquoted:
                current, mask, started = current + text, mask + flag * len(text), True
                continue
            for char in text:
                if char in _IFS_WHITESPACE:
                    if started:
                        fields.append((current, mask))
                        current, mask, started = "", "", False
                else:
                    current, mask, started = current + char, mask + flag, True
        if started:
            fields.append((current, mask))
        return fields

    def qpot_glob_dots(self) -> bool:
        """Whether a pattern that starts with a dot also matches . and ..: it does in BusyBox ash and in
        bash before 5.2, whose globskipdots (on by default) stopped it. The bash is the one `bash
        --version` names: the patch layer's coreutils derives it from the persona's os-release
        (centos-7, rhel-9 and the jammy personas have 4.2 or 5.1), else [shell] bash_version."""
        if CowrieConfig.get("shell", "not_found_style", fallback="bash") != "bash":
            return True
        try:
            from cowrie.commands.coreutils import qpot_bash_version

            text = qpot_bash_version(self.context.protocol.fs) or ""  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - without the patch layer's coreutils, the configured one
            text = ""
        found = re.search(r"version (\d+)\.(\d+)", text or CowrieConfig.get("shell", "bash_version", fallback=""))
        return bool(found) and (int(found.group(1)), int(found.group(2))) < (5, 2)

    @classmethod
    def qpot_glob_pattern(cls, part: str, pmask: str) -> str:
        """One part of a path (no slash) as an fnmatch pattern: a quoted pattern character matches
        itself, a bracket expression keeps its meaning (``[^...]`` negates as ``[!...]`` does, a POSIX
        class becomes its C-locale ranges), a ``[`` that no ``]`` closes is literal."""
        out: list[str] = []
        j, n = 0, len(part)
        while j < n:
            char = part[j]
            if pmask[j] != "1" or char != "[":
                out.append("[" + char + "]" if pmask[j] != "1" and char in "*?[]" else char)
                j += 1
                continue
            k = j + 1
            if k < n and part[k] in "!^":
                k += 1
            if k < n and part[k] == "]":
                k += 1
            while k < n and part[k] != "]":
                if part.startswith("[:", k) and part.find(":]", k + 2) > 0:
                    k = part.find(":]", k + 2) + 2
                    continue
                k += 1
            if k >= n:
                out.append("[[]")
                j += 1
                continue
            body = part[j + 1:k]
            if body[:1] == "^":
                body = "!" + body[1:]
            body = re.sub(r"\[:([a-z]+):\]", lambda m: cls.QPOT_GLOB_CLASSES.get(m.group(1), m.group(0)), body)
            out.append("[" + body + "]")
            j = k + 1
        return "".join(out)

    def qpot_pathnames(self, text: str, mask: str, budget: list[int] | None = None) -> list[str]:
        """The names text matches as a pattern, sorted; text itself when it has no active pattern
        character, matches nothing, or the filesystem cannot be read (bash without nullglob). budget
        holds the directory entries the command may still look at and the bytes of names it may still
        expand to; past either a word stays as typed.
        It walks the tree's nodes (a path lookup per name walked the tree from / each time, and
        `echo /*/*/*/*` took half a second), resolving only the links it goes through."""
        import fnmatch
        import posixpath

        from cowrie.shell.fs import A_CONTENTS, A_NAME, A_TYPE, T_DIR, T_LINK

        if budget is None:
            budget = [self.QPOT_GLOB_SCAN, self.QPOT_GLOB_BYTES]
        if not any(mask[i] == "1" and text[i] in "*?[" for i in range(len(text))) or len(text) > 4096:
            return [text]
        try:
            fs = self.context.protocol.fs  # type: ignore[attr-defined]
            cwd = str(self.context.cwd)  # type: ignore[attr-defined]
        except AttributeError:
            return [text]
        # the parts of the path, each as an fnmatch pattern (a literal part as None) and its text
        parts: list[tuple[str | None, str]] = []
        start, i = 0, 0
        while i <= len(text):
            if i == len(text) or text[i] == "/":
                part, pmask = text[start:i], mask[start:i]
                if any(pmask[j] == "1" and part[j] in "*?[" for j in range(len(part))):
                    parts.append((self.qpot_glob_pattern(part, pmask), part))
                else:
                    parts.append((None, part))
                start = i + 1
            i += 1
        base, shown = cwd, ""
        if text.startswith("/"):
            base, shown, parts = "/", "/", parts[1:]
        elif parts and parts[0] == (None, "~") and mask[:1] == "1":
            home = self.context.get_variable("HOME") or ""
            if not home.startswith("/"):
                return [text]
            base, shown, parts = home, home.rstrip("/") + "/", parts[1:]
        base = posixpath.normpath(base)
        dots = self.qpot_glob_dots()

        def lookup(path: str) -> list | None:
            """The node at a normalized absolute path, links followed (Cowrie's getfile knows no . or ..)."""
            budget[0] -= 16  # a walk from / for each link gone through
            try:
                return fs.getfile(path)
            except Exception:  # noqa: BLE001 - a link loop or an unreadable tree leads nowhere
                return None

        def through(path: str, node: list | None) -> list | None:
            """What a name leads to when a later part looks inside it: a link's target."""
            return lookup(path) if node is not None and node[A_TYPE] == T_LINK else node

        matches: list[tuple[str, str, list | None]] = [(shown, base, lookup(base))]
        for n, (pattern, part) in enumerate(parts):
            last = n == len(parts) - 1
            found: list[tuple[str, str, list | None]] = []
            for shown_so_far, path, node in matches:
                if part == "" and not last:
                    found.append((shown_so_far, path, node))  # a doubled slash
                    continue
                if part == "":
                    # a trailing slash: directories only, named with it
                    if node is not None and node[A_TYPE] == T_DIR:
                        found.append((shown_so_far.rstrip("/") + "/", path, node))
                    continue
                if node is None or node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
                    continue
                sep = "" if shown_so_far in ("", "/") or shown_so_far.endswith("/") else "/"
                children = node[A_CONTENTS]
                budget[0] -= len(children)
                if budget[0] < 0:
                    return [text]
                if pattern is None:
                    full = posixpath.normpath(posixpath.join(path, part))
                    if part in (".", ".."):
                        child = lookup(full)
                    else:
                        child = next((c for c in children if c[A_NAME] == part), None)
                    if child is not None:
                        found.append((shown_so_far + sep + part, full, child if last else through(full, child)))
                    continue
                named = [(c[A_NAME], c) for c in children if c[A_NAME] not in (".", "..")]
                if dots and pattern.startswith("."):
                    named += [(".", node), ("..", None)]
                for name, child in named:
                    if name.startswith(".") and not pattern.startswith("."):
                        continue
                    if fnmatch.fnmatchcase(name, pattern):
                        full = posixpath.normpath(posixpath.join(path, name))
                        if name == "..":
                            child = lookup(full)
                        found.append((shown_so_far + sep + name, full, child if last else through(full, child)))
            matches = found
            if not matches:
                return [text]
        names = sorted(shown_name for shown_name, _, _ in matches)
        size = sum(len(name) + 1 for name in names)
        if size > budget[1]:
            return [text]
        budget[1] -= size
        return names

    @staticmethod
    def _split_fields(pieces: list[tuple[str, bool] | None]) -> list[str]:
        """Join a word's pieces into fields, splitting unquoted expansions.

        ``pieces`` pairs each atom's text with whether it came from an unquoted
        expansion; ``None`` marks a ``"$@"`` parameter boundary, which always
        ends the current field. Whitespace inside unquoted text ends the
        current field; other text, and any quoted text even when empty,
        extends it.
        """
        fields: list[str] = []
        current = ""
        started = False
        for piece in pieces:
            if piece is None:
                fields.append(current)
                current = ""
                started = False
                continue
            text, unquoted = piece
            if not unquoted:
                current += text
                started = True
                continue
            for char in text:
                if char in _IFS_WHITESPACE:
                    if started:
                        fields.append(current)
                        current = ""
                        started = False
                else:
                    current += char
                    started = True
        if started:
            fields.append(current)
        return fields

    async def _eval_atom(self, line: str, atom: Tree | Token) -> str:
        if isinstance(atom, Token):
            if atom.type == "ESC":
                # Unquoted backslash escape: the backslash is removed.
                return str(atom.value)[1:]
            return str(atom.value)

        if atom.data == "sq":
            return self._leaf_value(atom)[1:-1]  # strip surrounding quotes
        if atom.data == "dollar_var" or atom.data == "dollar_brace":
            return self._expand_embedded(atom)
        if atom.data == "arith":
            # T-Pot: $(( )) of the persona's shell
            return await tpot_arith_value(self.context, str(atom.children[0])[3:-2])
        if atom.data == "cmdsub":
            return await self.context.command_substitution(
                self._group_source(line, atom)
            )
        if atom.data == "backtick":
            return await self.context.command_substitution(
                self._backtick_source(line, atom)
            )
        return ""

    async def _eval_dquoted(self, line: str, dq: Tree) -> list[str]:
        """Evaluate a double-quoted string to its segments.

        It is one segment, except that ``$@`` expands each positional
        parameter to a segment of its own: text before it joins the first
        parameter, text after it the last. A string of only ``$@`` with no
        positional parameters has no segments at all, so ``"$@"`` then
        yields no word.
        """
        segments = [""]
        only_at = True
        for part in dq.children:
            if isinstance(part, Tree) and self._is_at(part):
                params = self._positional_params()
                if params:
                    segments[-1] += params[0]
                    segments.extend(params[1:])
                continue
            only_at = False
            segments[-1] += await self._eval_dquoted_part(line, part)
        if only_at and dq.children and not self._positional_params():
            return []
        return segments

    async def _eval_dquoted_part(self, line: str, part: Tree | Token) -> str:
        if isinstance(part, Token):
            if part.type in ("DQ_TEXT", "BARE_DOLLAR"):
                return str(part.value)
            if part.type == "DQ_ESC":
                return self._unescape_dq(part.value)
            return ""
        if part.data == "dollar_var" or part.data == "dollar_brace":
            return self._expand_embedded(part)
        if part.data == "arith":
            return await tpot_arith_value(self.context, str(part.children[0])[3:-2])
        if part.data == "cmdsub":
            return await self.context.command_substitution(
                self._group_source(line, part)
            )
        if part.data == "backtick":
            return await self.context.command_substitution(
                self._backtick_source(line, part)
            )
        return ""

    def _is_at(self, node: Tree) -> bool:
        """Whether a node is the ``$@`` special parameter."""
        return (
            node.data in ("dollar_var", "dollar_brace")
            and self._var_name(node)[1] == "@"
        )

    def _positional_params(self) -> list[str]:
        """The positional parameters $1..$#, in order."""
        count = self.context.get_variable("#")
        if count is None or not count.isdigit():
            return []
        return [
            self.context.get_variable(str(i)) or "" for i in range(1, int(count) + 1)
        ]

    def _unescape_dq(self, text: str) -> str:
        # Inside double quotes a backslash is literal unless it precedes one of
        # \ " $ ` ; only then is it removed.
        if len(text) == 2 and text[1] in '\\"$`':
            return text[1]
        return text

    def _expand_embedded(self, node: Tree) -> str:
        """Expand a ``$VAR`` reference that is embedded in a larger word.

        A set variable expands to its value (empty included); an unset
        reference expands to the empty string, as bash does for an unquoted or
        double-quoted reference. A single-quoted reference is kept literal by
        the grammar (it never reaches here), so quoted awk/sed field references
        still survive.
        """
        special = self._special_param(node)
        if special is not None:
            return special
        name = self._var_name(node)[0]
        if name.endswith("]"):
            # QPot: ${NAME[N]}, ${NAME[@]}: the shell keeps no arrays, so a variable is its own element 0
            #   (as in bash); BASH_VERSINFO's elements come from BASH_VERSION and MACHTYPE
            return qpot_subscript(self.context, name)
        value = self.context.get_variable(name)
        if value is None:
            return ""
        return value

    def _special_param(self, node: Tree) -> str | None:
        """Expand a special parameter ($?, $@, $#, ...) to its string value, or
        None for an ordinary ``$name`` reference the caller should look up.

        ``$?`` is the last exit status. ``$@`` / ``$#`` / ``$*`` resolve to the
        positional parameters the shell sets while running a function or
        script; with none set, ``$@`` / ``$*`` are empty and ``$#`` is 0.
        Other specials are kept verbatim.
        """
        _, special = self._var_name(node)
        if special is None:
            return None
        if special == "?":
            return self.context.get_status()
        if special == "$":
            # T-Pot: $$ is the PID of the login shell
            return tpot_shell_pid(self.context)
        if special in ("@", "#", "*"):
            value = self.context.get_variable(special)
            if value is None:
                return "0" if special == "#" else ""
            return value
        if node.data == "dollar_brace":
            return "${" + self._leaf_value(node) + "}"
        return self._leaf_value(node)

    def _leaf_value(self, node: Tree) -> str:
        """Return the string value of a node's single leaf token."""
        token = node.children[0]
        assert isinstance(token, Token)
        return str(token)

    def _var_name(self, node: Tree) -> tuple[str, str | None]:
        """Return (name, special) for a dollar_var/dollar_brace node."""
        if node.data == "dollar_brace":
            name = self._leaf_value(node)
            return name, name if name in _SPECIAL_PARAMS else None
        tok = node.children[0]
        assert isinstance(tok, Token)
        text = str(tok)
        if tok.type == "DOLLAR_SPECIAL":
            return text, text[1:]
        return text[1:], None  # DOLLAR_NAME: strip leading $

    # -- source slicing for substitution / subshells ------------------------

    def _subshell_statements(self, line: str, subshell: Tree) -> list[Statement]:
        """Parse the ``body`` tree of a ``(...)`` group into statements."""
        for child in subshell.children:
            if isinstance(child, Tree) and child.data == "body":
                return self._split_statements(line, child)
        return []

    def _group_source(self, line: str, node: Tree) -> str:
        """Raw source of the inner ``start`` tree of a ``$(...)`` or ``(...)``."""
        for child in node.children:
            if isinstance(child, Tree) and child.data == "start":
                if child.meta.empty:
                    return ""
                return self._slice(line, child.meta.start_pos, child.meta.end_pos)
        return ""

    def _backtick_source(self, line: str, node: Tree) -> str:
        if node.meta.empty:
            return ""
        # Drop the surrounding backtick delimiters from the matched span.
        return self._slice(line, node.meta.start_pos + 1, node.meta.end_pos - 1)

    def _error_token(self, line: str, subshell: Tree) -> str:
        """Reconstruct bash's reported token for a misplaced ``(``.

        bash points at the ``(`` together with the run of non-space characters
        that follow it, e.g. ``(echo`` for ``( echo middle )`` written as
        ``(echo middle)``.
        """
        start = subshell.meta.start_pos
        end = start + 1
        while end < len(line) and not line[end].isspace() and line[end] != ")":
            end += 1
        return line[start:end]
