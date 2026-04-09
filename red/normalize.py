"""Text normalization pipeline.

Normalizes raw samples (command lines, registry keys, URLs, etc.) through:
  1. Filter dummy characters (" ^ ` ')
  2. Lowercase
  3. Tokenize on word boundaries (\\w+)
  4. Remove hex/numeric tokens longer than max_num_len
  5. Remove string tokens longer than max_str_len
  6. Sort tokens alphabetically, join with comma

This produces a canonical representation that reduces noise while
preserving semantically meaningful tokens for TF-IDF vectorization.
"""

import re
from typing import List


class Normalizer:
    """Normalize a single text sample into a sorted, comma-separated token string."""

    def __init__(self, max_num_len: int = 3, max_str_len: int = 30):
        self._dummy_re = re.compile(r'["\^`\']')
        self._word_re = re.compile(r"(\w+)")
        # Matches hex (0x...) or pure hex-digit strings longer than max_num_len
        self._num_re = re.compile(
            r"^(?:0x)?[0-9a-f]{" + str(max_num_len + 1) + r",}$"
        )
        self._max_str_len = max_str_len

    def normalize(self, sample: str) -> str:
        """Normalize a raw text sample.

        Parameters
        ----------
        sample : str
            Raw text (command line, URL, registry key, etc.).

        Returns
        -------
        str
            Comma-separated sorted tokens, or empty string if nothing remains.
        """
        if not isinstance(sample, str):
            sample = str(sample)

        # 1. Filter dummy characters
        text = self._dummy_re.sub("", sample)
        # 2. Lowercase
        text = text.lower()
        # 3. Tokenize on word boundaries
        tokens = self._word_re.findall(text)
        # 4. Remove long numeric / hex tokens
        tokens = [t for t in tokens if not self._num_re.match(t)]
        # 5. Remove long string tokens
        tokens = [t for t in tokens if len(t) <= self._max_str_len]
        # 6. Sort and join
        tokens.sort()
        return ",".join(tokens)


def normalize_samples(samples: List[str]) -> List[str]:
    """Normalize a list of samples, dropping any that become empty.

    Parameters
    ----------
    samples : list of str
        Raw text samples.

    Returns
    -------
    list of str
        Non-empty normalized samples.
    """
    normalizer = Normalizer()
    results = []
    for s in samples:
        n = normalizer.normalize(s)
        if n:
            results.append(n)
    return results
