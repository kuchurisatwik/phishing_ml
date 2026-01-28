# phishing_pipeline/__init__.py
"""Lightweight package init — avoid importing heavy submodules at import time."""

__version__ = "0.1"
__all__ = ["run_pipeline", "package_results"]

def run_pipeline(*args, **kwargs):
    from .pipeline import run_pipeline as _run_pipeline
    return _run_pipeline(*args, **kwargs)
 
def package_results(*args, **kwargs):
    from .pipeline import package_results as _package_results
    return _package_results(*args, **kwargs)
