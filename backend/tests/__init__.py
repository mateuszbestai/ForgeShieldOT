# Ensure the test environment (DATABASE_URL, auth bypass, mock AI provider, ...)
# is configured before anything under ``app.`` is imported anywhere in the suite.
from tests import _env  # noqa: F401
