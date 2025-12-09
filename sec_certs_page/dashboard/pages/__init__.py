"""Dashboard pages package.

This package contains the individual page layouts for each collection type.
Pages are automatically registered with Dash via `dash.register_page()`.

Pages:
- home: Main dashboard selection page (/)
- cc: Common Criteria collection dashboard (/cc)
- fips: FIPS 140 collection dashboard (/fips)
"""

# Import pages to trigger registration
from . import cc, common, fips
