#!/usr/bin/env python3
"""Generate deterministic reproduction payloads for mini-httpd."""

from pathlib import Path


def main() -> None:
    out = Path(__file__).resolve().parent / "input"
    out.mkdir(exist_ok=True)
    (out / "body-overflow.bin").write_bytes(
        b"POST / HTTP/1.1\r\n\r\n" + b"B" * 2000
    )
    (out / "long-path.bin").write_bytes(
        b"GET /" + b"A" * 4000 + b" HTTP/1.1\r\n\r\n"
    )
    print(f"Wrote payloads to {out}")


if __name__ == "__main__":
    main()
