"""The unit of change (Operation) and a batch of them (Plan).

An Operation is one CRUD/command call against a RouterOS menu path. Each
mutating Operation carries an `inverse` Operation that undoes it, which is what
makes safe rollback possible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# action constants
ADD = "add"
SET = "set"
REMOVE = "remove"
RUN = "run"  # a non-CRUD command, e.g. /system/backup/save

_SYMBOL = {ADD: "+", SET: "~", REMOVE: "-", RUN: ">"}


@dataclass
class Operation:
    action: str                       # add | set | remove | run
    path: tuple                       # e.g. ("ip", "firewall", "address-list")
    params: dict = field(default_factory=dict)
    desc: str = ""                    # human-readable one-liner
    inverse: "Operation | None" = None  # how to undo this op (for rollback)

    def menu(self) -> str:
        return "/" + "/".join(self.path)

    def line(self) -> str:
        return f"{_SYMBOL.get(self.action, '?')} {self.desc or (self.action + ' ' + self.menu())}"


@dataclass
class Plan:
    device: str
    ops: list = field(default_factory=list)
    summary: str = ""

    @property
    def empty(self) -> bool:
        return not self.ops

    def diff_text(self) -> str:
        """A human-readable preview of what apply() would do."""
        if self.empty:
            return f"{self.device}: already in the desired state — no changes."
        head = f"{self.device}: {len(self.ops)} change(s)"
        if self.summary:
            head += f" [{self.summary}]"
        return head + "\n" + "\n".join("  " + op.line() for op in self.ops)
