from typing import Callable, Any
from datetime import datetime, timedelta, timezone
from functools import cached_property
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import ValidationError
from sqlalchemy import create_engine, Engine, func, inspect, text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Mapped, mapped_column
import jwt, uuid, secrets, json, base64, requests
from jwt import PyJWKClient

from ._env_vars import SquirrelsEnvVars
from ._manifest import PermissionScope
from ._exceptions import InvalidInputError, ConfigurationError
from ._arguments.init_time_args import AuthProviderArgs
from ._schemas.auth_models import (
    CustomUserFields, AbstractUser, RegisteredUser, ApiKey, UserField, UserFieldsModel, AuthProvider, ProviderConfigs
)
from ._schemas import response_models as rm
from . import _utils as u, _constants as c

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ProviderFunctionType = Callable[[AuthProviderArgs], AuthProvider]


class Authenticator:
    providers: list[ProviderFunctionType] = []  # static variable to stage providers

    def __init__(
        self, logger: u.Logger, env_vars: SquirrelsEnvVars, auth_args: AuthProviderArgs, 
        provider_functions: list[ProviderFunctionType], custom_user_fields_cls: type[CustomUserFields], 
        *, 
        sa_engine: Engine | None = None, external_only: bool = False
    ):
        self.logger = logger
        self.env_vars = env_vars
        self.secret_key = env_vars.secret_key
        self.external_only = external_only
        self.password_requirements = rm.PasswordRequirements()

        # Create a new declarative base for this instance
        self.Base = declarative_base()
        
        # Define DbUser class for this instance
        class DbUser(self.Base):
            __tablename__ = 'users'
            __table_args__ = {'extend_existing': True}
            username: Mapped[str] = mapped_column(primary_key=True)
            access_level: Mapped[str] = mapped_column(nullable=False, default="member")
            password_hash: Mapped[str] = mapped_column(nullable=False)
            custom_fields: Mapped[str] = mapped_column(nullable=False, default="{}")
            created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
        
        # Define DbApiKey class for this instance
        class DbApiKey(self.Base):
            __tablename__ = 'api_keys'
            
            id: Mapped[str] = mapped_column(primary_key=True, default=lambda: uuid.uuid4().hex)
            hashed_key: Mapped[str] = mapped_column(unique=True, nullable=False)
            last_four: Mapped[str] = mapped_column(nullable=False)
            title: Mapped[str] = mapped_column(nullable=False)
            username: Mapped[str] = mapped_column(ForeignKey('users.username', ondelete='CASCADE'), nullable=False)
            created_at: Mapped[datetime] = mapped_column(nullable=False)
            expires_at: Mapped[datetime] = mapped_column(nullable=False)
        
            def __repr__(self):
                return f"<DbApiKey(id='{self.id}', username='{self.username}')>"
        
        self.CustomUserFields = custom_user_fields_cls
        self.DbUser = DbUser

        self.DbApiKey = DbApiKey
        
        self.auth_providers = [provider_function(auth_args) for provider_function in provider_functions]
        self._jwks_clients: dict[str, PyJWKClient] = {}
        self._provider_metadata_cache: dict[str, dict] = {}
        
        if not self.external_only:
            if sa_engine is None:
                raw_sqlite_path = self.env_vars.auth_db_file_path
                sqlite_path = u.Path(raw_sqlite_path.format(project_path=self.env_vars.project_path))
                sqlite_path.parent.mkdir(parents=True, exist_ok=True)
                self.engine = create_engine(f"sqlite:///{str(sqlite_path)}")
            else:
                self.engine = sa_engine
            
            # Configure SQLite pragmas
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode = WAL"))
                conn.execute(text("PRAGMA synchronous = NORMAL"))
                conn.commit()
            
            self.Base.metadata.create_all(self.engine)

            self.Session = sessionmaker(bind=self.engine)

            self._initialize_db()
    
    def _convert_db_user_to_user(self, db_user) -> RegisteredUser:
        """Convert a database user to an AbstractUser object"""
        # Deserialize custom_fields JSON and merge with defaults
        custom_fields_json = json.loads(db_user.custom_fields) if db_user.custom_fields else {}
        custom_fields = self.CustomUserFields(**custom_fields_json)
        
        return RegisteredUser(
            username=db_user.username, 
            access_level=db_user.access_level,
            custom_fields=custom_fields
        )
    
    def _validate_password_length(self, password: str) -> None:
        """Validate that password meets length requirements and does not exceed 72 characters (bcrypt limit)"""
        min_len = self.password_requirements.min_length
        max_len = min(self.password_requirements.max_length, 72)
        if len(password) < min_len:
            raise InvalidInputError(400, "password_too_short", f"Password must be at least {min_len} characters long")
        if len(password) > max_len:
            raise InvalidInputError(400, "password_too_long", f"Password cannot exceed {max_len} characters")
    
    def _initialize_db(self):
        session = self.Session()
        try:
            # Get existing columns in the database
            inspector = inspect(self.engine)
            
            for db_model in [self.DbUser, self.DbApiKey]:
                table_name = db_model.__tablename__
                existing_columns = {col['name'] for col in inspector.get_columns(table_name)}
                model_columns = set(db_model.__table__.columns.keys())
                new_columns = model_columns - existing_columns
                
                if new_columns:
                    add_columns_msg = f"Adding columns to table {table_name}: {new_columns}"
                    self.logger.info(add_columns_msg)
                    
                    for col_name in new_columns:
                        col = db_model.__table__.columns[col_name]
                        column_type = col.type.compile(self.engine.dialect)
                        nullable = "NULL" if col.nullable else "NOT NULL"
                        if col.default is not None and not callable(col.default.arg):
                            default_val = f"'{col.default.arg}'" if isinstance(col.default.arg, str) else col.default.arg
                            default = f"DEFAULT {default_val}"
                        else:
                            # If nullable is False and no default is provided, use an empty string as a placeholder default for SQLite
                            # TODO: Use a different default value (instead of empty string) based on the column type
                            default = "DEFAULT ''" if not col.nullable else ""
                        
                        alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {column_type} {nullable} {default}"
                        session.execute(text(alter_stmt))
                    
                    session.commit()

            # Get admin password from environment variable if exists
            admin_password = self.env_vars.secret_admin_password
            
            if admin_password is not None:
                self._validate_password_length(admin_password)
                password_hash = pwd_context.hash(admin_password)
                admin_user = session.get(self.DbUser, c.ADMIN_USERNAME)
                if admin_user is None:
                    admin_user = self.DbUser(username=c.ADMIN_USERNAME, password_hash=password_hash, access_level="admin")
                    session.add(admin_user)
                else:
                    admin_user.password_hash = password_hash
            
            session.commit()

        finally:
            session.close()

    @cached_property
    def user_fields(self) -> UserFieldsModel:
        """
        Get the fields of the CustomUserFields model as a list of dictionaries
        
        Each dictionary contains the following keys:
        - name: The name of the field
        - type: The type of the field
        - nullable: Whether the field is nullable
        - enum: The possible values of the field (or None if not applicable)
        - default: The default value of the field (or None if field is required)
        """
        
        custom_fields = []
        schema = self.CustomUserFields.model_json_schema()
        properties: dict[str, dict[str, Any]] = schema.get("properties", {})
        for field_name, field_schema in properties.items():
            if choices := field_schema.get("anyOf"):
                field_type = choices[0]["type"]
                nullable = (choices[1]["type"] == "null")
            else:
                field_type = field_schema["type"]
                nullable = False
            
            field_data = UserField(name=field_name, label=field_schema.get("title", field_name), type=field_type, nullable=nullable, enum=field_schema.get("enum"), default=field_schema.get("default"))
            custom_fields.append(field_data)

        return UserFieldsModel(
            username=UserField(name="username", label="Username / Email", type="string", nullable=False, enum=None, default=None), 
            access_level=UserField(name="access_level", label="Access Level", type="string", nullable=False, enum=["admin", "member"], default="member"),
            custom_fields=custom_fields
        )
    
    def add_user(self, username: str, user_fields: dict, *, update_user: bool = False) -> RegisteredUser:
        # Separate custom fields from base fields
        access_level = user_fields.get('access_level', 'member')
        password = user_fields.get('password')
        
        # Validate access level - cannot add/update users with guest access level
        if access_level == "guest":
            raise InvalidInputError(400, "invalid_access_level", "Cannot create or update users with 'guest' access level")
        
        # Extract custom fields
        custom_fields_data: dict[str, Any] = user_fields.get('custom_fields', {})
        
        # Validate the custom fields
        try:
            custom_fields = self.CustomUserFields(**custom_fields_data)
            custom_fields_json = json.dumps(custom_fields.model_dump(mode='json'))
        except ValidationError as e:
            raise InvalidInputError(400, "invalid_user_data", f"Invalid user field '{e.errors()[0]['loc'][0]}': {e.errors()[0]['msg']}")

        # Add or update user
        session = self.Session()
        try:
            # Check if the user already exists
            db_user = session.get(self.DbUser, username)
            if db_user is not None:
                if not update_user:
                    raise InvalidInputError(400, "username_already_exists", f"User '{username}' already exists")
                
                if username == c.ADMIN_USERNAME and access_level != "admin":
                    raise InvalidInputError(403, "admin_cannot_be_non_admin", "Setting the admin user to non-admin is not permitted")
                
                # Update existing user
                db_user.access_level = access_level
                db_user.custom_fields = custom_fields_json
            else:
                if update_user:
                    raise InvalidInputError(404, "no_user_found_for_username", f"No user found for username: {username}")
                
                if password is None:
                    raise InvalidInputError(400, "missing_password", f"Missing required field 'password' when adding a new user")
                
                self._validate_password_length(password)
                password_hash = pwd_context.hash(password)
                db_user = self.DbUser(
                    username=username,
                    access_level=access_level,
                    password_hash=password_hash,
                    custom_fields=custom_fields_json
                )
                session.add(db_user)
            
            # Commit the transaction
            session.commit()
            return self._convert_db_user_to_user(db_user)

        finally:
            session.close()
    
    def create_or_get_user_from_provider(self, provider_name: str, user_info: dict) -> RegisteredUser:
        provider = next((p for p in self.auth_providers if p.name == provider_name), None)
        if provider is None:
            raise InvalidInputError(404, "auth_provider_not_found", f"Provider '{provider_name}' not found")
        
        user = provider.provider_configs.get_user(user_info)
        session = self.Session()
        try:
            # Convert user to database user
            custom_fields_json = user.custom_fields.model_dump_json()
            db_user = self.DbUser(
                username=user.username,
                access_level=user.access_level,
                password_hash="",  # By omitting password_hash, it becomes impossible to login with username and password (OAuth only)
                custom_fields=custom_fields_json
            )

            existing_db_user = session.get(self.DbUser, db_user.username)
            if existing_db_user is None:
                session.add(db_user)
        
            session.commit()

            return self._convert_db_user_to_user(db_user)
        
        finally:
            session.close()

    def get_user(self, username: str, password: str) -> RegisteredUser:
        session = self.Session()
        try:
            # Query for user by username
            db_user = session.get(self.DbUser, username)
            
            if db_user and pwd_context.verify(password, db_user.password_hash):
                user = self._convert_db_user_to_user(db_user)
                return user
            else:
                raise InvalidInputError(401, "incorrect_username_or_password", f"Incorrect username or password")

        finally:
            session.close()
    
    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        session = self.Session()
        try:
            db_user = session.get(self.DbUser, username)
            if db_user is None:
                raise InvalidInputError(401, "user_not_found", f"Username '{username}' not found for password change")
            
            if db_user.password_hash and pwd_context.verify(old_password, db_user.password_hash):
                self._validate_password_length(new_password)
                db_user.password_hash = pwd_context.hash(new_password)
                session.commit()
            else:
                raise InvalidInputError(401, "incorrect_password", f"Incorrect password")
        finally:
            session.close()

    def delete_user(self, username: str) -> None:
        if username == c.ADMIN_USERNAME:
            raise InvalidInputError(403, "cannot_delete_admin_user", "Cannot delete the admin user")
        
        session = self.Session()
        try:
            db_user = session.get(self.DbUser, username)
            if db_user is None:
                raise InvalidInputError(404, "no_user_found_for_username", f"No user found for username: {username}")
            session.delete(db_user)
            session.commit()
        finally:
            session.close()

    def get_all_users(self) -> list[RegisteredUser]:
        session = self.Session()
        try:
            db_users = session.query(self.DbUser).all()
            return [self._convert_db_user_to_user(user) for user in db_users]
        finally:
            session.close()
    
    def create_access_token(self, user: AbstractUser, expiry_minutes: int | None, *, title: str | None = None) -> tuple[str, datetime]:
        """
        Creates an API key if title is provided. Otherwise, creates a JWT token.
        """
        created_at = datetime.now(timezone.utc)
        expire_at = created_at + timedelta(minutes=expiry_minutes) if expiry_minutes is not None else datetime.max
        
        if self.secret_key is None:
            raise ConfigurationError(f"Environment variable '{c.SQRL_SECRET_KEY}' is required to create an access token")
        
        if title is not None:
            session = self.Session()
            try:
                token_id = "sqrl-" + secrets.token_urlsafe(16)
                hashed_key = u.hash_string(token_id, salt=self.secret_key)
                last_four = token_id[-4:]
                api_key = self.DbApiKey(
                    hashed_key=hashed_key, last_four=last_four, title=title, username=user.username, 
                    created_at=created_at, expires_at=expire_at
                )
                session.add(api_key)
                session.commit()
            finally:
                session.close()
        else:
            to_encode = {"username": user.username, "exp": expire_at}
            token_id = jwt.encode(to_encode, self.secret_key, algorithm="HS256")
        
        return token_id, expire_at
    
    def get_user_from_token(self, token: str | None) -> tuple[RegisteredUser | None, float | None]:
        """
        Get a user and expiry time from an access token (JWT, or API key if token starts with 'sqrl-')
        """
        if not token:
            return None, None
        
        if self.secret_key is None:
            raise ConfigurationError(f"Environment variable '{c.SQRL_SECRET_KEY}' is required to get user from an access token")

        session = self.Session()
        try:
            if token.startswith("sqrl-"):
                hashed_key = u.hash_string(token, salt=self.secret_key)
                api_key = session.query(self.DbApiKey).filter(
                    self.DbApiKey.hashed_key == hashed_key,
                    self.DbApiKey.expires_at >= func.now()
                ).first()
                if api_key is None:
                    raise InvalidTokenError()
                username = api_key.username
                expiry = None
            else:
                payload: dict = jwt.decode(token, self.secret_key, algorithms=["HS256"])
                username = payload["username"]
                expiry = payload.get("exp")
                
            db_user = session.get(self.DbUser, username)
            if db_user is None:
                raise InvalidTokenError()
            
            user = self._convert_db_user_to_user(db_user)
        
        except InvalidTokenError:
            raise InvalidInputError(401, "invalid_authorization_token", "Invalid authorization token")
        finally:
            session.close()
        
        return user, expiry
    
    def _get_jwks_client(self, jwks_uri: str) -> PyJWKClient:
        if jwks_uri not in self._jwks_clients:
            self._jwks_clients[jwks_uri] = PyJWKClient(jwks_uri)
        return self._jwks_clients[jwks_uri]

    def _get_issuer_from_token(self, token: str) -> str | None:
        try:
            # JWT format is header.payload.signature
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Base64url decode the payload (JWT uses base64url encoding)
            payload_b64 = parts[1]
            # Add padding if necessary: (-len % 4) yields 0..3
            padding = '=' * ((-len(payload_b64)) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
            payload: dict = json.loads(payload_json)

            issuer = payload.get("iss")
            return issuer if isinstance(issuer, str) and issuer else None
        except Exception:
            return None

    @staticmethod
    def _is_jwt(token: str) -> bool:
        if not isinstance(token, str) or not token:
            return False
        parts = token.split(".")
        return len(parts) == 3 and all(parts)

    def _get_provider_metadata(self, provider_name: str) -> dict:
        provider = next((p for p in self.auth_providers if p.name == provider_name), None)
        if provider is None:
            raise InvalidInputError(404, "auth_provider_not_found", f"Provider '{provider_name}' not found")

        metadata_url = provider.provider_configs.server_metadata_url
        cached = self._provider_metadata_cache.get(metadata_url)
        if isinstance(cached, dict) and cached:
            return cached

        try:
            response = requests.get(metadata_url)
            response.raise_for_status()
            metadata = response.json()
            if not isinstance(metadata, dict):
                raise ValueError("Provider metadata was not a JSON object")
        except Exception as e:
            raise ConfigurationError(f"Failed to fetch metadata for provider '{provider_name}': {str(e)}")

        self._provider_metadata_cache[metadata_url] = metadata
        return metadata

    def _verify_provider_jwt(
        self,
        provider_name: str,
        token: str,
        *,
        purpose: str,
        expected_nonce: str | None = None,
        verify_aud: bool = True,
    ) -> dict | None:
        """
        Verify a provider-issued JWT (signature + exp; aud when requested).
        Uses OIDC discovery for jwks_uri and (best-effort) issuer validation.
        """
        if not self._is_jwt(token):
            return None

        provider = next((p for p in self.auth_providers if p.name == provider_name), None)
        if provider is None:
            raise InvalidInputError(404, "auth_provider_not_found", f"Provider '{provider_name}' not found")

        metadata = self._get_provider_metadata(provider_name)
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise ConfigurationError(f"jwks_uri not found in metadata for provider '{provider_name}'")

        signing_algs = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
        if not isinstance(signing_algs, list) or not signing_algs:
            signing_algs = ["RS256"]

        jwks_client = self._get_jwks_client(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        decode_kwargs: dict[str, Any] = {
            "key": signing_key.key,
            "algorithms": signing_algs,
            "options": {
                "verify_aud": bool(verify_aud),
                # We'll validate issuer manually to avoid brittle trailing-slash mismatches.
                "verify_iss": False,
            },
        }
        if verify_aud:
            decode_kwargs["audience"] = provider.provider_configs.client_id

        try:
            payload = jwt.decode(token, **decode_kwargs)
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        expected_issuer = metadata.get("issuer") or provider.provider_configs.server_url
        token_issuer = payload.get("iss")
        if isinstance(expected_issuer, str) and expected_issuer and isinstance(token_issuer, str) and token_issuer:
            if token_issuer.rstrip("/") != expected_issuer.rstrip("/"):
                raise InvalidInputError(
                    401,
                    "invalid_provider_token",
                    f"Invalid {purpose} issuer for provider '{provider_name}'",
                )

        if expected_nonce is not None:
            nonce_claim = payload.get("nonce")
            if nonce_claim != expected_nonce:
                raise InvalidInputError(
                    401,
                    "invalid_provider_token",
                    f"Invalid {purpose} nonce for provider '{provider_name}'",
                )

        return payload

    def get_user_info_from_token_details(self, provider_name: str, token_details: dict, *, expected_nonce: str | None = None) -> dict:
        """
        Determine user_info from an OAuth/OIDC token response.

        Priority:
        - token_details["user_info"] / token_details["userinfo"]
        - verify + decode token_details["id_token"] if it's a JWT
        - verify + decode token_details["access_token"] if it's a JWT
        - for opaque access_token: call userinfo or introspection endpoint from provider metadata
        """
        for key in ("user_info", "userinfo"):
            user_info = token_details.get(key)
            if isinstance(user_info, dict) and user_info:
                return user_info

        id_token = token_details.get("id_token")
        if isinstance(id_token, str):
            if payload := self._verify_provider_jwt(
                provider_name, id_token, purpose="id_token", expected_nonce=expected_nonce, verify_aud=True
            ):
                return payload

        access_token = token_details.get("access_token")
        if isinstance(access_token, str):
            # Some providers issue JWT access tokens. Audience can vary (resource server),
            # so we verify signature/exp and issuer, but skip aud validation.
            if payload := self._verify_provider_jwt(
                provider_name, access_token, purpose="access_token", expected_nonce=None, verify_aud=False
            ):
                return payload

        if not isinstance(access_token, str) or not access_token:
            raise InvalidInputError(
                400,
                "invalid_provider_user_info",
                f"User information not found in token details for {provider_name}",
            )

        provider = next((p for p in self.auth_providers if p.name == provider_name), None)
        if provider is None:
            raise InvalidInputError(404, "auth_provider_not_found", f"Provider '{provider_name}' not found")

        metadata: dict = self._get_provider_metadata(provider_name)

        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if isinstance(userinfo_endpoint, str) and userinfo_endpoint:
            try:
                response = requests.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
                user_info = response.json()
                if isinstance(user_info, dict) and user_info:
                    return user_info
            except Exception:
                # Fall back to introspection if available
                pass

        introspection_endpoint = metadata.get("introspection_endpoint")
        if isinstance(introspection_endpoint, str) and introspection_endpoint:
            try:
                response = requests.post(
                    introspection_endpoint,
                    data={"token": access_token},
                    auth=(provider.provider_configs.client_id, provider.provider_configs.client_secret),
                )
                response.raise_for_status()
                token_info = response.json()
                if isinstance(token_info, dict):
                    if token_info.get("active") is False:
                        raise InvalidInputError(401, "inactive_external_token", "External authorization token is inactive")
                    return token_info
            except InvalidInputError:
                raise
            except Exception:
                # Some providers require "client_secret_post" instead of basic auth for introspection.
                try:
                    response = requests.post(
                        introspection_endpoint,
                        data={
                            "token": access_token,
                            "client_id": provider.provider_configs.client_id,
                            "client_secret": provider.provider_configs.client_secret,
                        },
                    )
                    response.raise_for_status()
                    token_info = response.json()
                    if isinstance(token_info, dict):
                        if token_info.get("active") is False:
                            raise InvalidInputError(401, "inactive_external_token", "External authorization token is inactive")
                        return token_info
                except InvalidInputError:
                    raise
                except Exception:
                    pass

        raise InvalidInputError(
            400,
            "invalid_provider_user_info",
            f"User information not found in token details for {provider_name}",
        )

    def get_user_from_external_token(self, token: str, provider_name: str | None = None) -> tuple[RegisteredUser, float | None]:
        """
        Get a user from an external OAuth token by validating against provider's JWKS
        """
        issuer: str | None = None
        token_is_jwt = self._is_jwt(token)

        if provider_name:
            provider = next((p for p in self.auth_providers if p.name == provider_name), None)
        elif token_is_jwt:
            issuer = self._get_issuer_from_token(token)
            if not issuer:
                raise InvalidInputError(401, "invalid_external_token", "Could not extract issuer from token")

            # Match provider by issuer (server_url)
            provider = next(
                (p for p in self.auth_providers if p.provider_configs.server_url.rstrip("/") == issuer.rstrip("/")),
                None,
            )
        else:
            # Opaque external token: if there's exactly one configured provider, assume it.
            provider = self.auth_providers[0] if len(self.auth_providers) == 1 else None

        if provider is None:
            if provider_name:
                raise InvalidInputError(404, "auth_provider_not_found", f"Provider '{provider_name}' not found")
            if token_is_jwt:
                raise InvalidInputError(401, "auth_provider_not_found", f"No provider found for issuer: {issuer}")
            raise InvalidInputError(401, "invalid_external_token", "Could not determine provider for external token")

        # JWT external token: validate signature/exp (+ issuer) via provider JWKS
        if token_is_jwt:
            try:
                payload = self._verify_provider_jwt(provider.name, token, purpose="external_token", verify_aud=False)
            except InvalidInputError:
                # Keep the external-auth contract stable (avoid leaking provider-specific details).
                raise InvalidInputError(401, "invalid_external_token", "Invalid external authorization token")

            if not isinstance(payload, dict) or not payload:
                raise InvalidInputError(401, "invalid_external_token", "Invalid external authorization token")
        else:
            # Opaque token: reuse the existing provider userinfo/introspection logic.
            try:
                payload = self.get_user_info_from_token_details(provider.name, {"access_token": token})
            except InvalidInputError as e:
                # Normalize into the external-auth error contract.
                if getattr(e, "error", None) == "inactive_external_token":
                    raise
                raise InvalidInputError(401, "invalid_external_token", "Invalid external authorization token")

        if not isinstance(payload, dict) or not payload:
            raise InvalidInputError(401, "invalid_external_token", "Invalid external authorization token")

        user = provider.provider_configs.get_user(payload)
        exp = payload.get("exp")
        expiry: float | None
        if isinstance(exp, (int, float)):
            expiry = float(exp)
        else:
            expiry = None

        return user, expiry

    def get_all_api_keys(self, username: str) -> list[ApiKey]:
        """
        Get the ID, title, and expiry date of all API keys for a user. Note that the ID is a hash of the API key, not the API key itself.
        """
        session = self.Session()
        try:
            tokens = session.query(self.DbApiKey).filter(
                self.DbApiKey.username == username,
                self.DbApiKey.expires_at >= func.now()
            ).all()
            
            return [ApiKey.model_validate(token) for token in tokens]
        finally:
            session.close()
    
    def revoke_api_key(self, username: str, api_key_id: str) -> None:
        """
        Revoke an API key
        """
        session = self.Session()
        try:

            api_key = session.query(self.DbApiKey).filter(
                self.DbApiKey.username == username,
                self.DbApiKey.id == api_key_id
            ).first()
            
            if api_key is None:
                raise InvalidInputError(404, "api_key_not_found", f"The API key could not be found: {api_key_id}")
            
            session.delete(api_key)
            session.commit()
        finally:
            session.close()

    def can_user_access_scope(self, user: AbstractUser, scope: PermissionScope) -> bool:
        if user.access_level == "guest":
            user_level = PermissionScope.PUBLIC
        elif user.access_level == "admin":
            user_level = PermissionScope.PRIVATE
        else:  # member
            user_level = PermissionScope.PROTECTED
        
        return user_level.value >= scope.value
    
    def close(self) -> None:
        if hasattr(self, "engine"):
            self.engine.dispose()


def provider(name: str, label: str, icon: str):
    """
    Decorator to register an authentication provider

    Arguments:
        name: The name of the provider (must be unique, e.g. 'google')
        label: The label of the provider (e.g. 'Google')
        icon: The URL of the icon of the provider (e.g. 'https://www.google.com/favicon.ico')
    """
    def decorator(func: Callable[[AuthProviderArgs], ProviderConfigs]):
        def wrapper(sqrl: AuthProviderArgs):
            provider_configs = func(sqrl)
            return AuthProvider(name=name, label=label, icon=icon, provider_configs=provider_configs)
        Authenticator.providers.append(wrapper)
        return wrapper
    return decorator
