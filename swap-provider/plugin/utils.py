# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from datetime import datetime
from typing import (Union, Any,
                    Set, NamedTuple)
import aiorpcx
import decimal
from decimal import Decimal
import asyncio
import time
from typing import Optional, Sequence
import functools

from .globals import get_plugin_logger


_logger = get_plugin_logger()
bfh = bytes.fromhex


class BitcoinException(Exception): pass

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def _descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def _descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = _descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = _descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))

def inv_dict(d):
    return {v: k for k, v in d.items()}

def all_subclasses(cls) -> Set:
    """Return all (transitive) subclasses of cls."""
    res = set(cls.__subclasses__())
    for sub in res.copy():
        res |= all_subclasses(sub)
    return res

async def call_blocking_with_timeout(func, *args, timeout: int) -> Any:
    return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=timeout)

def parse_max_spend(amt: Any) -> Optional[int]:
    """Checks if given amount is "spend-max"-like.
    Returns None or the positive integer weight for "max". Never raises.

    When creating invoices and on-chain txs, the user can specify to send "max".
    This is done by setting the amount to '!'. Splitting max between multiple
    tx outputs is also possible, and custom weights (positive ints) can also be used.
    For example, to send 40% of all coins to address1, and 60% to address2:
    ```
    address1, 2!
    address2, 3!
    ```
    """
    if not (isinstance(amt, str) and amt and amt[-1] == '!'):
        return None
    if amt == '!':
        return 1
    x = amt[:-1]
    try:
        x = int(x)
    except ValueError:
        return None
    if x > 0:
        return x
    return None


class BelowDustLimit(Exception):
    pass

class TxBroadcastError(Exception):
    pass

class InvalidPassword(Exception):
    def __init__(self, message: Optional[str] = None):
        self.message = message

    def __str__(self):
        if self.message is None:
            return "Incorrect password"
        else:
            return str(self.message)


class WalletFileException(Exception):
    def __init__(self, message='', *, should_report_crash: bool = False):
        Exception.__init__(self, message)
        self.should_report_crash = should_report_crash





class UserFacingException(Exception):
    """Exception that contains information intended to be shown to the user."""


class InvoiceError(UserFacingException): pass


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except Exception:
        print('assert bytes failed', list(map(type, args)))
        raise


def to_string(x, enc) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")


def to_bytes(something, encoding='utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def age(
    from_date: Union[int, float, None],  # POSIX timestamp
    # *,
    since_date: datetime = None,
    target_tz=None,
    include_seconds: bool = False,
) -> str:
    """Takes a timestamp and returns a string with the approximation of the age"""
    if from_date is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    distance_in_time = from_date - since_date
    is_in_past = from_date < since_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds / 60))

    if distance_in_minutes == 0:
        if include_seconds:
            if is_in_past:
                return "{} seconds ago".format(distance_in_seconds)
            else:
                return "in {} seconds".format(distance_in_seconds)
        else:
            if is_in_past:
                return "less than a minute ago"
            else:
                return "in less than a minute"
    elif distance_in_minutes < 45:
        if is_in_past:
            return "about {} minutes ago".format(distance_in_minutes)
        else:
            return "in about {} minutes".format(distance_in_minutes)
    elif distance_in_minutes < 90:
        if is_in_past:
            return "about 1 hour ago"
        else:
            return "in about 1 hour"
    elif distance_in_minutes < 1440:
        if is_in_past:
            return "about {} hours ago".format(round(distance_in_minutes / 60.0))
        else:
            return "in about {} hours".format(round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        if is_in_past:
            return "about 1 day ago"
        else:
            return "in about 1 day"
    elif distance_in_minutes < 43220:
        if is_in_past:
            return "about {} days ago".format(round(distance_in_minutes / 1440))
        else:
            return "in about {} days".format(round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        if is_in_past:
            return "about 1 month ago"
        else:
            return "in about 1 month"
    elif distance_in_minutes < 525600:
        if is_in_past:
            return "about {} months ago".format(round(distance_in_minutes / 43200))
        else:
            return "in about {} months".format(round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        if is_in_past:
            return "about 1 year ago"
        else:
            return "in about 1 year"
    else:
        if is_in_past:
            return "over {} years ago".format(round(distance_in_minutes / 525600))
        else:
            return "in over {} years".format(round(distance_in_minutes / 525600))


def is_hex_str(text: Any) -> bool:
    if not isinstance(text, str): return False
    try:
        b = bytes.fromhex(text)
    except Exception:
        return False
    # forbid whitespaces in text:
    if len(text) != 2 * len(b):
        return False
    return True


def chunks(items, size: int):
    """Break up items, an iterable, into chunks of length size."""
    if size < 1:
        raise ValueError(f"size must be positive, not {repr(size)}")
    for i in range(0, len(items), size):
        yield items[i: i + size]


# # Check that Decimal precision is sufficient.
# # We need at the very least ~20, as we deal with msat amounts, and
# # log10(21_000_000 * 10**8 * 1000) ~= 18.3
# decimal.DefaultContext.prec == 28 by default, but it is mutable.
# We enforce that we have at least that available.
assert decimal.getcontext().prec >= 28, f"PyDecimal precision too low: {decimal.getcontext().prec}"

DECIMAL_POINT = "."
THOUSANDS_SEP = " "
assert len(DECIMAL_POINT) == 1, f"DECIMAL_POINT has unexpected len. {DECIMAL_POINT!r}"
assert len(THOUSANDS_SEP) == 1, f"THOUSANDS_SEP has unexpected len. {THOUSANDS_SEP!r}"


def format_satoshis(
        x: Union[int, float, Decimal, str, None],  # amount in satoshis
        *,
        num_zeros: int = 0,
        decimal_point: int = 8,  # how much to shift decimal point to left (default: sat->BTC)
        precision: int = 0,  # extra digits after satoshi precision
        is_diff: bool = False,  # if True, enforce a leading sign (+/-)
        whitespaces: bool = False,  # if True, add whitespaces, to align numbers in a column
        add_thousands_sep: bool = False,  # if True, add whitespaces, for better readability of the numbers
) -> str:
    if x is None:
        return 'unknown'
    if parse_max_spend(x):
        return f'max({x})'
    assert isinstance(x, (int, float, Decimal)), f"{x!r} should be a number"
    # lose redundant precision
    x = Decimal(x).quantize(Decimal(10) ** (-precision))
    # format string
    overall_precision = decimal_point + precision  # max digits after final decimal point
    decimal_format = "." + str(overall_precision) if overall_precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    # initial result
    scale_factor = pow(10, decimal_point)
    result = ("{:" + decimal_format + "f}").format(x / scale_factor)
    if "." not in result: result += "."
    result = result.rstrip('0')
    # add extra decimal places (zeros)
    integer_part, fract_part = result.split(".")
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    # add whitespaces as thousands' separator for better readability of numbers
    if add_thousands_sep:
        sign = integer_part[0] if integer_part[0] in ("+", "-") else ""
        if sign == "-":
            integer_part = integer_part[1:]
        integer_part = "{:,}".format(int(integer_part)).replace(',', THOUSANDS_SEP)
        integer_part = sign + integer_part
        fract_part = THOUSANDS_SEP.join(fract_part[i:i+3] for i in range(0, len(fract_part), 3))
    result = integer_part + DECIMAL_POINT + fract_part
    # add leading/trailing whitespaces so that numbers can be aligned in a column
    if whitespaces:
        target_fract_len = overall_precision
        target_integer_len = 14 - decimal_point  # should be enough for up to unsigned 999999 BTC
        if add_thousands_sep:
            target_fract_len += max(0, (target_fract_len - 1) // 3)
            target_integer_len += max(0, (target_integer_len - 1) // 3)
        # add trailing whitespaces
        result += " " * (target_fract_len - len(fract_part))
        # add leading whitespaces
        target_total_len = target_integer_len + 1 + target_fract_len
        result = " " * (target_total_len - len(result)) + result
    return result


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


def log_exceptions(func):
    """Decorator to log AND re-raise exceptions."""
    assert asyncio.iscoroutinefunction(func), 'func needs to be a coroutine'
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        self = args[0] if len(args) > 0 else None
        try:
            return await func(*args, **kwargs)
        except asyncio.CancelledError as e:
            raise
        except BaseException as e:
            mylogger = self.logger if hasattr(self, 'logger') else _logger
            try:
                mylogger.exception(f"Exception in {func.__name__}: {repr(e)}")
            except BaseException as e2:
                print(f"logging exception raised: {repr(e2)}... orig exc: {repr(e)} in {func.__name__}")
            raise
    return wrapper


class TxMinedInfo(NamedTuple):
    height: int                        # height of block that mined tx
    conf: Optional[int] = None         # number of confirmations, SPV verified. >=0, or None (None means unknown)
    timestamp: Optional[int] = None    # timestamp of block that mined tx
    txpos: Optional[int] = None        # position of tx in serialized block
    header_hash: Optional[str] = None  # hash of block that mined tx
    wanted_height: Optional[int] = None  # in case of timelock, min abs block height

    def short_id(self) -> Optional[str]:
        if self.txpos is not None and self.txpos >= 0:
            assert self.height > 0
            return f"{self.height}x{self.txpos}"
        return None


class ShortID(bytes):

    def __repr__(self):
        return f"<ShortID: {format_short_id(self)}>"

    def __str__(self):
        return format_short_id(self)

    @classmethod
    def from_components(cls, block_height: int, tx_pos_in_block: int, output_index: int) -> 'ShortID':
        bh = block_height.to_bytes(3, byteorder='big')
        tpos = tx_pos_in_block.to_bytes(3, byteorder='big')
        oi = output_index.to_bytes(2, byteorder='big')
        return ShortID(bh + tpos + oi)

    @classmethod
    def from_str(cls, scid: str) -> 'ShortID':
        """Parses a formatted scid str, e.g. '643920x356x0'."""
        components = scid.split("x")
        if len(components) != 3:
            raise ValueError(f"failed to parse ShortID: {scid!r}")
        try:
            components = [int(x) for x in components]
        except ValueError:
            raise ValueError(f"failed to parse ShortID: {scid!r}") from None
        return ShortID.from_components(*components)

    @classmethod
    def normalize(cls, data: Union[None, str, bytes, 'ShortID']) -> Optional['ShortID']:
        if isinstance(data, ShortID) or data is None:
            return data
        if isinstance(data, str):
            assert len(data) == 16
            return ShortID.fromhex(data)
        if isinstance(data, (bytes, bytearray)):
            assert len(data) == 8
            return ShortID(data)

    @property
    def block_height(self) -> int:
        return int.from_bytes(self[:3], byteorder='big')

    @property
    def txpos(self) -> int:
        return int.from_bytes(self[3:6], byteorder='big')

    @property
    def output_index(self) -> int:
        return int.from_bytes(self[6:8], byteorder='big')


def format_short_id(short_channel_id: Optional[bytes]):
    if not short_channel_id:
        return 'Not yet available'
    return str(int.from_bytes(short_channel_id[:3], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[3:6], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[6:], 'big'))


class OldTaskGroup(aiorpcx.TaskGroup):
    """Automatically raises exceptions on join; as in aiorpcx prior to version 0.20.
    That is, when using TaskGroup as a context manager, if any task encounters an exception,
    we would like that exception to be re-raised (propagated out). For the wait=all case,
    the OldTaskGroup class is emulating the following code-snippet:
    ```
    async with TaskGroup() as group:
        await group.spawn(task1())
        await group.spawn(task2())

        async for task in group:
            if not task.cancelled():
                task.result()
    ```
    So instead of the above, one can just write:
    ```
    async with OldTaskGroup() as group:
        await group.spawn(task1())
        await group.spawn(task2())
    ```
    # TODO see if we can migrate to asyncio.timeout, introduced in python 3.11, and use stdlib instead of aiorpcx.curio...
    """
    async def join(self):
        if self._wait is all:
            exc = False
            try:
                async for task in self:
                    if not task.cancelled():
                        task.result()
            except BaseException:  # including asyncio.CancelledError
                exc = True
                raise
            finally:
                if exc:
                    await self.cancel_remaining()
                await super().join()
        else:
            await super().join()
            if self.completed:
                self.completed.result()

def list_enabled_bits(x: int) -> Sequence[int]:
    """e.g. 77 (0b1001101) --> (0, 2, 3, 6)"""
    binary = bin(x)[2:]
    rev_bin = reversed(binary)
    return tuple(i for i, b in enumerate(rev_bin) if b == '1')


class classproperty(property):
    """~read-only class-level @property
    from https://stackoverflow.com/a/13624858 by denis-ryzhkov
    """
    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)

def now():
    return int(time.time())
