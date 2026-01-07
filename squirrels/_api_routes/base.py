"""
Base utilities and dependencies for API routes
"""
from typing import Any, Mapping, TypeVar, Callable, Coroutine, Literal
from textwrap import dedent
from fastapi import Request, Response, Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from cachetools import TTLCache
from pathlib import Path
from datetime import datetime, timezone

from .. import _utils as u
from .._exceptions import InvalidInputError
from .._project import SquirrelsProject
from .._schemas.auth_models import AbstractUser
from .._dataset_types import DatasetResultFormat

T = TypeVar('T')


class RouteBase:
    """Base class for route modules providing common functionality"""
    
    def __init__(self, get_bearer_token: HTTPBearer, project: SquirrelsProject, no_cache: bool = False):
        self.project = project
        self.no_cache = no_cache
        self.logger = project._logger
        self.env_vars = project._env_vars
        self.manifest_cfg = project._manifest_cfg
        self.authenticator = project._auth
        self.param_cfg_set = project._param_cfg_set
        
        # Setup templates
        template_dir = Path(__file__).parent.parent / "_package_data" / "templates"
        self.templates = Jinja2Templates(directory=str(template_dir))
    
        # Authorization dependency for current user
        def get_token_from_session(request: Request) -> str | None:
            access_token = request.session.get("access_token")
            if access_token is None: return None
            
            expiry = request.session.get("access_token_expiry")
            datetime_now = datetime.now(timezone.utc).timestamp()
            if expiry and expiry > datetime_now:
                return access_token
            
            raise InvalidInputError(401, "session_expired", "Login session expired. Please login again.")
        
        def get_user_from_headers(api_key: str | None, bearer_token: str | None) -> AbstractUser:
            final_token = api_key if api_key else bearer_token
            user = self.authenticator.get_user_from_token(final_token)
            if user is None:
                user = self.project._guest_user
            
            return user
        
        async def get_current_user(
            request: Request, response: Response, 
            x_api_key: str | None = Header(None, description="API key for authentication (alternative to Authorization header)"), 
            auth: HTTPAuthorizationCredentials = Depends(get_bearer_token)
        ) -> AbstractUser:
            token = auth.credentials if auth and auth.scheme == "Bearer" else None
            access_token = token if token else get_token_from_session(request)
            user = get_user_from_headers(x_api_key, access_token)
            response.headers["Applied-Username"] = user.username
            return user

        self.get_user_from_headers = get_user_from_headers
        self.get_current_user = get_current_user
        
    @property
    def _parameters_description(self) -> str:
        """Get the standard parameters description"""
        return dedent("""
            Selections of one parameter may cascade the available options in another parameter. 
            
            For example, if the dataset has parameters for 'country' and 'city', available options for 'city' would depend on the selected option 'country'. 
            
            If a parameter has `"trigger_refresh": true` and its selection changes, provide the parameter selection to this endpoint to refresh the parameter options of children parameters.
        """).strip()
    
    def get_selections_as_immutable(self, params: Mapping, uncached_keys: set[str]) -> tuple[tuple[str, Any], ...]:
        """Convert selections into a cachable tuple of pairs"""
        selections = list()
        for key, val in params.items():
            if key in uncached_keys or val is None:
                continue
            if isinstance(val, (list, tuple)):
                val = tuple(val)
            selections.append((u.normalize_name(key), val))
        return tuple(selections)

    async def do_cachable_action(self, cache: TTLCache, action: Callable[..., Coroutine[Any, Any, T]], *args) -> T:
        """Execute a cachable action"""
        cache_key = tuple(args)
        result = cache.get(cache_key)
        if result is None:
            result = await action(*args)
            cache[cache_key] = result
        return result
    
    def get_name_from_path_section(self, request: Request, section: int) -> str:
        """Extract name from request path section"""
        url_path: str = request.url.path
        name_raw = url_path.split('/')[section]
        return u.normalize_name(name_raw)

    def get_configurables_from_headers(self, headers: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
        """Extract configurables from request headers with prefix 'x-config-'."""
        prefix = "x-config-"
        cfg_pairs: list[tuple[str, str]] = []
        seen_configurables: dict[str, str] = {}  # normalized_name -> header_name

        for key, value in headers.items():
            key_lower = str(key).lower()
            if key_lower.startswith(prefix):
                cfg_name_raw = key_lower[len(prefix):]
                cfg_name_normalized = u.normalize_name(cfg_name_raw)  # Convert to underscore convention

                # Check if we've already seen this configurable (with different header format)
                if cfg_name_normalized in seen_configurables:
                    existing_header = seen_configurables[cfg_name_normalized]
                    raise InvalidInputError(
                        400, "duplicate_configurable_header",
                        f"Only one header format is allowed for configurable '{cfg_name_normalized}'. "
                        f"Both '{existing_header}' and '{key_lower}' were provided."
                    )

                seen_configurables[cfg_name_normalized] = key_lower
                cfg_pairs.append((cfg_name_normalized, str(value)))

        configurables = [k for k, _ in cfg_pairs]
        self.logger.info(f"Configurables specified: {configurables}", data={"configurables_specified": configurables})
        return tuple(cfg_pairs)

    @staticmethod
    def extract_orientation_offset_and_limit(
        params: Mapping[str, Any], *,
        key_prefix: str = "x_",
        default_orientation: Literal["records", "rows", "columns"] = "records",
        default_offset: int = 0, default_limit: int = 1000
    ) -> DatasetResultFormat:
        """
        Extract orientation, offset, and limit from query parameters.

        Args:
            params: Query parameters

        Returns:
            Tuple of (orientation, offset, limit)
        """
        # Handle orientation
        orientation = str(params.get(f"{key_prefix}orientation", default_orientation)).lower()

        if orientation not in ["records", "rows", "columns"]:
            raise InvalidInputError(400, "invalid_orientation", f"Orientation must be 'records', 'rows', or 'columns'. Invalid orientation provided: {orientation}")

        # Handle limit and offset
        offset = int(params.get(f"{key_prefix}offset", default_offset))
        limit = int(params.get(f"{key_prefix}limit", default_limit))

        if offset < 0:
            raise InvalidInputError(400, "invalid_offset", "Offset must be non-negative")

        if limit < 0:
            raise InvalidInputError(400, "invalid_limit", "Limit must be non-negative")
        
        return DatasetResultFormat(orientation, offset, limit)
    