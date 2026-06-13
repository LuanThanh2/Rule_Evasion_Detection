#!/usr/bin/env python3
"""
Extract URLs from SecRepo Squid access.log → benign_train.txt for proxy_web.

Squid access.log format:
  timestamp elapsed client action/result bytes method URL user hierarchy content-type

Usage:
    python3 secrepo_to_benign.py \
        --input ~/KLTN/KLTN/datasets/benign_data/access.log/access.log \
        --output-dir ~/data/benign/proxy_web
"""

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def convert(input_path: str, output_dir: str):
    in_path = Path(input_path)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    urls = set()
    skipped = 0

    with open(in_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 7:
                skipped += 1
                continue

            method = parts[5]   # GET, POST, HEAD, CONNECT...
            url = parts[6]      # http://... or host:port

            # Skip CONNECT (HTTPS tunnel — only host:port, not full URL)
            if method == "CONNECT":
                skipped += 1
                continue

            # Keep only http/https URLs
            if not (url.startswith("http://") or url.startswith("https://")):
                skipped += 1
                continue

            urls.add(url)

    out_file = out_path / "benign_train.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        for url in sorted(urls):
            f.write(url + "\n")

    logger.info("URLs extracted: %d (skipped: %d) → %s", len(urls), skipped, out_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to access.log")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    convert(args.input, args.output_dir)


if __name__ == "__main__":
    main()
