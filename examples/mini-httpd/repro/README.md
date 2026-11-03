# mini-httpd reproduction

This directory contains a deterministic AddressSanitizer reproduction for the
seeded findings in `src/handler.c`.

## 1. Build

From the repository root:

```bash
mkdir -p /tmp/vulnforge-repro
gcc -g -O0 -fno-stack-protector -fsanitize=address \
  -I examples/mini-httpd/src \
  -o /tmp/vulnforge-repro/harness \
  examples/mini-httpd/repro/harness.c \
  examples/mini-httpd/src/handler.c
```

GCC and Clang both support these flags. No network access is required.

## 2. Generate payloads

```bash
python3 examples/mini-httpd/repro/payloads.py
```

This creates:

- `examples/mini-httpd/repro/input/body-overflow.bin`
- `examples/mini-httpd/repro/input/long-path.bin`

## 3. Run

```bash
/tmp/vulnforge-repro/harness \
  < examples/mini-httpd/repro/input/body-overflow.bin
```

Expected result:

```text
==...==ERROR: AddressSanitizer: heap-buffer-overflow
    #1 ... in parse_request examples/mini-httpd/src/handler.c:38
```

Then run:

```bash
/tmp/vulnforge-repro/harness \
  < examples/mini-httpd/repro/input/long-path.bin
```

Expected result:

```text
==...==ERROR: AddressSanitizer: heap-buffer-overflow
    #1 ... in parse_request examples/mini-httpd/src/handler.c:32
```

A non-zero exit status is expected. This is a deliberately vulnerable test
target and must not be deployed.
