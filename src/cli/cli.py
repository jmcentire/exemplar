"""Script entry point for exemplar CLI, plus emission-compliant Cli class."""
import sys

from cli import (
    build_parser,
    parse_and_validate_args,
    handle_review,
    handle_trust,
    handle_history,
    handle_adopt,
    build_dispatch_table,
    map_decision_to_exit_code,
    main,
)


# ---------------------------------------------------------------------------
# Emission-compliant class wrapper
# ---------------------------------------------------------------------------

PACT_COMPONENT = "cli"


def _emit_event(handler, event: str, pact_key: str, **kwargs) -> None:
    if handler is None:
        return
    try:
        handler({"event": event, "pact_key": pact_key, **kwargs})
    except Exception:
        pass


class Cli:
    """Class wrapper around CLI functions for PACT emission compliance."""

    def __init__(self, event_handler=None) -> None:
        self._handler = event_handler

    def build_parser(self):
        pact_key = f"PACT:{PACT_COMPONENT}:build_parser"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = build_parser()
            _emit_event(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def parse_and_validate_args(self, parser=None, argv=None):
        pact_key = f"PACT:{PACT_COMPONENT}:parse_and_validate_args"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if parser is None or argv is None:
                raise TypeError("parser and argv are required")
            result = parse_and_validate_args(parser, argv)
            _emit_event(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def handle_review(self, args=None):
        pact_key = f"PACT:{PACT_COMPONENT}:handle_review"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if args is None:
                raise TypeError("args is required")
            raise TypeError("Use the async handle_review function directly")
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def handle_trust(self, args=None):
        pact_key = f"PACT:{PACT_COMPONENT}:handle_trust"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if args is None:
                raise TypeError("args is required")
            raise TypeError("Use the async handle_trust function directly")
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def handle_history(self, args=None):
        pact_key = f"PACT:{PACT_COMPONENT}:handle_history"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if args is None:
                raise TypeError("args is required")
            raise TypeError("Use the async handle_history function directly")
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def handle_adopt(self, args=None):
        pact_key = f"PACT:{PACT_COMPONENT}:handle_adopt"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if args is None:
                raise TypeError("args is required")
            raise TypeError("Use the async handle_adopt function directly")
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def build_dispatch_table(self):
        pact_key = f"PACT:{PACT_COMPONENT}:build_dispatch_table"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = build_dispatch_table()
            _emit_event(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def map_decision_to_exit_code(self, decision=None):
        pact_key = f"PACT:{PACT_COMPONENT}:map_decision_to_exit_code"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if decision is None:
                raise TypeError("decision is required")
            result = map_decision_to_exit_code(decision)
            _emit_event(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise

    def main(self, argv=None):
        pact_key = f"PACT:{PACT_COMPONENT}:main"
        _emit_event(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = main(argv or [])
            _emit_event(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit_event(self._handler, "error", pact_key, error=str(e))
            raise


if __name__ == "__main__":
    sys.exit(main())
