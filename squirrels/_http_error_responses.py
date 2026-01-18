from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from ._exceptions import InvalidInputError


def _strip_path_suffix_from_base_url(request: Request, *, strip_path_suffix: str | None) -> str:
    """
    Return a base URL with a known mount suffix removed.

    In Squirrels, the main app mounts sub-apps like `/api/0` and `/mcp`. When we're
    handling a request inside those sub-apps, `request.base_url` includes the mount
    path. For `WWW-Authenticate` we want to point to a top-level endpoint on the main
    app (same mount as the main app itself), so we strip only the *sub-app mount*
    suffix (e.g. `/api/0` or `/mcp`), not any outer mount path.
    """
    base_url = str(request.base_url).rstrip("/")
    if strip_path_suffix:
        suffix = strip_path_suffix.rstrip("/")
        if suffix and base_url.endswith(suffix):
            base_url = base_url[: -len(suffix)]
    return base_url.rstrip("/")


def invalid_input_error_to_json_response(
    request: Request,
    exc: InvalidInputError,
    *,
    oauth_resource_metadata_path: str = "/.well-known/oauth-protected-resource",
    strip_path_suffix: str | None = None,
    is_mcp: bool = False,
) -> JSONResponse:
    """
    Convert an InvalidInputError into the standard Squirrels JSON error response.

    For 401s, also sets `WWW-Authenticate` with a top-level `resource_metadata` URL.
    """
    response = JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.error_description},
    )

    if exc.status_code == 401:
        top_level_base_url = _strip_path_suffix_from_base_url(request, strip_path_suffix=strip_path_suffix)
        resource_metadata_url = f"{top_level_base_url}{oauth_resource_metadata_path}"
        realm = "mcp" if is_mcp else "api"
        response.headers["WWW-Authenticate"] = f'Bearer realm="{realm}", resource_metadata="{resource_metadata_url}"'

    return response

