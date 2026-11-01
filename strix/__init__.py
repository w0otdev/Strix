# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

from .context import INNER_NAME, VER
from .runtime import pipeline

__author__ = "w0otdev"
__license__ = "Apache-2.0"
__version__ = VER
__all__ = ["INNER_NAME", "VER", "pipeline"]
