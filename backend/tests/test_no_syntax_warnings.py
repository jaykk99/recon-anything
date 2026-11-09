"""Lint gate: no module may emit a SyntaxWarning.

Invalid escape sequences in non-raw strings (e.g. a regex written '\\s'
instead of r'\\s', or '\\b' which silently becomes a backspace) are the
bug class that let a detection rule match the wrong thing. CPython warns
on them today and will make them a hard SyntaxError in a future version.
This gate catches them at the source, before they ship.

Pure compile() - no imports, no third-party deps, no network.
"""
import pathlib
import warnings

APP = pathlib.Path(__file__).resolve().parent.parent / "app"


def test_no_syntax_warnings_anywhere():
    offenders = []
    for f in sorted(APP.rglob("*.py")):
        src = f.read_text(encoding="utf-8", errors="replace")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                compile(src, str(f), "exec")
            except SyntaxError as e:  # noqa: BLE001
                offenders.append(f"{f}: SyntaxError: {e}")
                continue
            for w in caught:
                if issubclass(w.category, SyntaxWarning):
                    rel = f.relative_to(APP.parent)
                    offenders.append(f"{rel}:{w.lineno}: {w.message}")
    assert not offenders, (
        "SyntaxWarning(s) found - write regex strings as raw (r'...') or "
        "double the backslash:\n" + "\n".join(offenders))
