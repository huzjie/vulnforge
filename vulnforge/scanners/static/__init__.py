"""Static rule-based scanner package.

Contains the rule data model, the matcher, the scanner, and the bundled rule
library.  Importing this package registers :class:`StaticScanner` so it is
discoverable through the scanner registry.
"""

from .rule import StaticRule
from .matcher import StaticMatcher
from .scanner import StaticScanner
from .rules import RULES, register_all

__all__ = ["StaticRule", "StaticMatcher", "StaticScanner", "RULES", "register_all"]
