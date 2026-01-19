"""
Authentication and user management routes
"""
from datetime import datetime, timezone
import secrets
from typing import Annotated, Literal
from urllib.parse import quote
from fastapi import FastAPI, Depends, Request, Response, Form, APIRouter
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from authlib.integrations.starlette_client import OAuth

from .. import _utils as u
from .._schemas import response_models as rm
from .._exceptions import InvalidInputError
from .._schemas.auth_models import AbstractUser, RegisteredUser, GuestUser, UserFieldsModel, ApiKey
from .._manifest import AuthStrategy
from .base import RouteBase


class AuthRoutes(RouteBase):
    """Authentication and user management routes"""
    
    def __init__(self, get_bearer_token: HTTPBearer, project, no_cache: bool = False):
        super().__init__(get_bearer_token, project, no_cache)

    @staticmethod
    def _get_base_url_for_current_app(request: Request) -> str:
        """
        Build the absolute base URL for the *current* mounted app, including `root_path`.

        We avoid `request.url_for(...)` because route names can collide when multiple Squirrels
        FastAPI apps are mounted into the same root app.
        """
        base_url = f"{request.url.scheme}://{request.url.netloc}"
        root_path = str(request.scope.get("root_path") or "").rstrip("/")
        return f"{base_url}{root_path}"
        
    def setup_routes(self, app: FastAPI) -> None:
        """Setup all authentication routes"""

        auth_path = "/auth"
        auth_router = APIRouter(prefix=auth_path)
        user_management_router = APIRouter(prefix=auth_path + "/user-management")
        
        auth_strategy = self.manifest_cfg.project_variables.auth_strategy
        is_external = (auth_strategy == AuthStrategy.EXTERNAL)

        # Get expiry configuration
        expiry_mins = self.env_vars.auth_token_expire_minutes
        
        # Create user models
        class CustomFieldsModel(self.authenticator.CustomUserFields):
            pass

        class UpdateUserModel(BaseModel):
            access_level: Literal["admin", "member"] = Field(description="The access level of the user. Admins have more permissions such as creating and updating users.")
            custom_fields: CustomFieldsModel = Field(description="User fields that are specific to this Squirrels project")

        class UserInfoModel(UpdateUserModel):
            username: str

        class AddUserModel(UserInfoModel):
            password: str
        
        class UserSessionModel(BaseModel):
            user: UserInfoModel
            session_expiry_timestamp: float | None

        # Setup OAuth2 login providers
        oauth = OAuth()

        for provider in self.authenticator.auth_providers:
            oauth.register(
                name=provider.name,
                server_metadata_url=provider.provider_configs.server_metadata_url,
                client_id=provider.provider_configs.client_id,
                client_secret=provider.provider_configs.client_secret,
                client_kwargs=provider.provider_configs.client_kwargs
            )

        # User info endpoint
        user_session_path = '/user-session'

        @auth_router.get(user_session_path, description="Get the authenticated user's fields", tags=["Authentication"])
        async def get_user_session(
            request: Request, user: RegisteredUser | GuestUser = Depends(self.get_current_user)
        ) -> UserSessionModel:
            if isinstance(user, GuestUser):
                raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token, no user info found")
            
            expiry = request.session.get("access_token_expiry")
            if expiry is None:
                expiry = getattr(request.state, "access_token_expiry", None)
            
            user_session = UserSessionModel(
                user=user.model_dump(mode='json'), 
                session_expiry_timestamp=float(expiry) if expiry is not None else None
            )
            return user_session

        # Login endpoint
        if not is_external:
            login_path = '/login'
            
            @auth_router.post(login_path, tags=["Authentication"], description="Authenticate with username & password. Returns user information if no redirect_url is provided, otherwise redirects to the specified URL.")
            async def login(
                request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()]
            ) -> UserSessionModel:
                user = self.authenticator.get_user(username, password)
                
                access_token, expiry = self.authenticator.create_access_token(user, expiry_minutes=expiry_mins)
                expiry_timestamp = expiry.timestamp()
                request.session["access_token"] = access_token
                request.session["access_token_expiry"] = expiry_timestamp

                user_session = UserSessionModel(user=user.model_dump(mode='json'), session_expiry_timestamp=expiry_timestamp)
                return user_session
        
        # Provider authentication endpoints
        providers_path = '/providers'
        provider_login_path = '/providers/{provider_name}/login'
        provider_callback_path = '/providers/{provider_name}/callback'

        @auth_router.get(providers_path, tags=["Authentication"])
        async def get_providers(request: Request) -> list[rm.ProviderResponse]:
            """Get list of available authentication providers"""
            base_url = self._get_base_url_for_current_app(request)

            def get_icon_url(icon: str) -> str:
                if icon.startswith("/public/"):
                    return base_url + icon
                return icon

            return [
                rm.ProviderResponse(
                    name=provider.name,
                    label=provider.label,
                    icon=get_icon_url(provider.icon),
                    login_url=f"{base_url}{auth_path}/providers/{quote(provider.name)}/login",
                )
                for provider in self.authenticator.auth_providers
            ]

        @auth_router.get(provider_login_path, tags=["Authentication"], responses={
            307: {"description": "Redirect to sign in with provider"},
        })
        async def provider_login(request: Request, provider_name: str, redirect_url: str | None = None) -> RedirectResponse:
            """
            Redirect to the login URL for the OAuth provider. 
            
            If login is successful, this endpoint redirects to the specified `redirect_url`. If no `redirect_url` is provided, it returns the user information of the Squirrels project's user.
            """
            client = oauth.create_client(provider_name)
            if client is None:
                raise InvalidInputError(status_code=404, error="provider_not_found", error_description=f"Provider {provider_name} not found or configured.")

            base_url = self._get_base_url_for_current_app(request)
            callback_uri = f"{base_url}{auth_path}/providers/{quote(provider_name)}/callback"
            request.session["redirect_url"] = redirect_url
            
            # OIDC best practice: include a nonce when requesting an id_token.
            # Not all providers will use it, but major OIDC providers support it.
            nonce = secrets.token_urlsafe(24)
            request.session[f"oidc_nonce:{provider_name}"] = nonce

            # PKCE: Some providers (e.g. Keycloak) require the authorization request to include
            # `code_challenge_method=S256`. We also store the verifier so we can send it when
            # exchanging the authorization code for tokens.
            code_verifier = secrets.token_urlsafe(64)  # ~86 chars; within 43-128 PKCE range
            request.session[f"pkce_verifier:{provider_name}"] = code_verifier
            code_challenge = u.generate_pkce_challenge(code_verifier)

            return await client.authorize_redirect(
                request,
                callback_uri,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )

        @auth_router.get(provider_callback_path, tags=["Authentication"], responses={
            307: {"description": "Redirect to redirect_url provided from provider login"},
        })
        async def provider_callback(request: Request, provider_name: str):
            """Handle OAuth callback from provider"""
            client = oauth.create_client(provider_name)
            if client is None:
                raise InvalidInputError(status_code=404, error="provider_not_found", error_description=f"Provider {provider_name} not found or configured.")

            try:
                code_verifier = request.session.pop(f"pkce_verifier:{provider_name}", None)
                if code_verifier is None:
                    token_details: dict = await client.authorize_access_token(request)
                else:
                    token_details = await client.authorize_access_token(request, code_verifier=code_verifier)
            except Exception as e:
                raise InvalidInputError(status_code=400, error="provider_authorization_failed", error_description=f"Could not authorize with provider for access token: {str(e)}")
            
            if is_external:
                # Prefer id_token (JWT) for session auth if available. Many providers (e.g. Google)
                # issue opaque access tokens that do not contain an issuer, which breaks provider
                # auto-detection for session-based auth.
                access_token = token_details.get("access_token")
                id_token = token_details.get("id_token")
                if isinstance(id_token, str) and id_token and id_token.count(".") == 2:
                    access_token = id_token

                if not isinstance(access_token, str) or not access_token:
                    raise InvalidInputError(400, "provider_missing_access_token", f"Provider token not found for {provider_name}")

                expires_in = token_details.get("expires_in")
                if expires_in is None:
                    # Fallback for providers that only return absolute expiry
                    expiry_timestamp = token_details.get("expires_at")
                    if expiry_timestamp is None:
                        raise InvalidInputError(400, "provider_missing_expiry", f"Provider expiry timestamp not found for {provider_name}")
                else:
                    expiry_timestamp = datetime.now(timezone.utc).timestamp() + float(expires_in)
            else:
                expected_nonce = request.session.pop(f"oidc_nonce:{provider_name}", None)
                user_info = self.authenticator.get_user_info_from_token_details(
                    provider_name, token_details, expected_nonce=expected_nonce
                )
                user = self.authenticator.create_or_get_user_from_provider(provider_name, user_info)
                access_token, expiry = self.authenticator.create_access_token(user, expiry_minutes=expiry_mins)
                expiry_timestamp = expiry.timestamp()
            
            request.session["access_token"] = access_token
            request.session["access_token_expiry"] = expiry_timestamp

            redirect_url = request.session.pop("redirect_url", None)
            if redirect_url:
                return RedirectResponse(url=redirect_url)
            
            base_url = self._get_base_url_for_current_app(request)
            return RedirectResponse(url=f"{base_url}{auth_path}/user-session")

        # Logout endpoint
        logout_path = '/logout'
        
        @auth_router.post(logout_path, tags=["Authentication"])
        async def logout(request: Request):
            """Logout the current user by clearing the access token and expiry from the session"""
            request.session.pop("access_token", None)
            request.session.pop("access_token_expiry", None)
            return Response(status_code=200)
        
        if not is_external:
            # Change password endpoint
            change_password_path = '/password'

            class ChangePasswordRequest(BaseModel):
                old_password: str
                new_password: str

            @auth_router.put(change_password_path, description="Change the password for the current user", tags=["Authentication"])
            async def change_password(request: ChangePasswordRequest, user: RegisteredUser | GuestUser = Depends(self.get_current_user)) -> None:
                if isinstance(user, GuestUser):
                    raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token")
                self.authenticator.change_password(user.username, request.old_password, request.new_password)

            # API Key endpoints
            api_key_path = '/api-keys'

            class ApiKeyRequestBody(BaseModel):
                title: str = Field(description=f"The title of the API key")
                expiry_minutes: int | None = Field(
                    default=None, 
                    description=f"The number of minutes the API key is valid for (or valid indefinitely if not provided)."
                )

            @auth_router.post(api_key_path, description="Create a new API key for the user", tags=["Authentication"])
            async def create_api_key(body: ApiKeyRequestBody, user: RegisteredUser | GuestUser = Depends(self.get_current_user)) -> rm.ApiKeyResponse:
                if isinstance(user, GuestUser):
                    raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token, cannot create API key")
                
                api_key, _ = self.authenticator.create_access_token(user, expiry_minutes=body.expiry_minutes, title=body.title)
                return rm.ApiKeyResponse(api_key=api_key)
            
            @auth_router.get(api_key_path, description="Get all API keys with title for the current user", tags=["Authentication"])
            async def get_all_api_keys(user: RegisteredUser | GuestUser = Depends(self.get_current_user)) -> list[ApiKey]:
                if isinstance(user, GuestUser):
                    raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token, cannot get API keys")
                return self.authenticator.get_all_api_keys(user.username)
            
            revoke_api_key_path = '/api-keys/{key_id}'

            @auth_router.delete(revoke_api_key_path, description="Revoke an API key", tags=["Authentication"], responses={
                204: { "description": "API key revoked successfully" }
            })
            async def revoke_api_key(key_id: str, user: RegisteredUser | GuestUser = Depends(self.get_current_user)) -> Response:
                if isinstance(user, GuestUser):
                    raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token, cannot revoke API key")
                self.authenticator.revoke_api_key(user.username, key_id)
                return Response(status_code=204)

        app.include_router(auth_router)

        # User management endpoints (disabled if external auth only)
        if is_external: 
            return

        user_fields_path = '/user-fields'

        @user_management_router.get(user_fields_path, description="Get details of the user fields", tags=["User Management"])
        async def get_user_fields() -> UserFieldsModel:
            return self.authenticator.user_fields
        
        list_or_add_users_path = '/users'
        update_or_delete_user_path = '/users/{username}'

        @user_management_router.get(list_or_add_users_path, tags=["User Management"])
        async def list_all_users(user: AbstractUser = Depends(self.get_current_user)) -> list[UserInfoModel]:
            if user.access_level != "admin":
                raise InvalidInputError(403, "unauthorized_to_list_users", "Current user does not have permission to list users")
            return self.authenticator.get_all_users()
        
        @user_management_router.post(list_or_add_users_path, description="Add a new user by providing details for username, password, and user fields", tags=["User Management"])
        async def add_user(
            new_user: AddUserModel, user: AbstractUser = Depends(self.get_current_user)
        ) -> UserInfoModel:
            if user.access_level != "admin":
                raise InvalidInputError(403, "unauthorized_to_add_user", "Current user does not have permission to add new users")
            return self.authenticator.add_user(new_user.username, new_user.model_dump(mode='json', exclude={"username"}))

        @user_management_router.put(update_or_delete_user_path, description="Update the user of the given username given the new user details", tags=["User Management"])
        async def update_user(
            username: str, updated_user: UpdateUserModel, user: AbstractUser = Depends(self.get_current_user)
        ) -> UserInfoModel:
            if user.access_level != "admin":
                raise InvalidInputError(403, "unauthorized_to_update_user", "Current user does not have permission to update users")
            return self.authenticator.add_user(username, updated_user.model_dump(mode='json'), update_user=True)

        @user_management_router.delete(update_or_delete_user_path, tags=["User Management"], responses={
            204: { "description": "User deleted successfully" }
        })
        async def delete_user(username: str, user: AbstractUser = Depends(self.get_current_user)) -> Response:
            if user.access_level != "admin":
                raise InvalidInputError(403, "unauthorized_to_delete_user", "Current user cannot delete users")
            if username == user.username:
                raise InvalidInputError(403, "cannot_delete_own_user", "Cannot delete your own user")
            self.authenticator.delete_user(username)
            return Response(status_code=204)

        app.include_router(user_management_router)
