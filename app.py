#!/usr/bin/env python3

import sys
from seal import get_unsealed_secret


def main():
    """
    Example application that retrieves a sealed secret at startup
    and uses it to configure something (e.g., HTTP client).
    """

    try:
        secret = get_unsealed_secret()
    except Exception as e:
        # Fail fast if we cannot decrypt – this is almost always fatal
        print(f"[app] Failed to retrieve secret: {e}", file=sys.stderr)
        sys.exit(1)

    # From here on, you can use `secret` as e.g. an API key, DB password, etc.
    # For demo purposes, we just print the length (not the actual secret).
    print("[app] Successfully retrieved secret.")
    print(f"[app] Secret length: {len(secret)} characters")


if __name__ == "__main__":

    main()
