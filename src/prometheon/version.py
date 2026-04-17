"""Single source of truth for the package version.

The version is duplicated in ``pyproject.toml`` (the build metadata).
Release tooling keeps the two values in lockstep.
"""

# Semantic version. Bumped per release. Phase 1 starts at 0.x while the
# protocol surface is still under active iteration; the 1.x line is reserved
# for the first deployment-ready cut.
__version__ = "0.1.0"
