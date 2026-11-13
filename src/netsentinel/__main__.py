"""Allow ``python -m netsentinel`` to start NetSentinel."""

from netsentinel.app import main


if __name__ == "__main__":
    raise SystemExit(main())
