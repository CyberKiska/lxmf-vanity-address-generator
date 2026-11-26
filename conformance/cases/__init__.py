"""Case registry. Each module listed in MODULES exposes CASES, a list of harness.Case."""

import importlib

MODULES = ("smoke", "cli_grammar", "cli_validation")


def load_cases():
    cases, seen = [], set()
    for name in MODULES:
        for case in importlib.import_module(f"{__name__}.{name}").CASES:
            if case.id in seen:
                raise ValueError(f"duplicate case id {case.id}")
            seen.add(case.id)
            cases.append(case)
    return cases
