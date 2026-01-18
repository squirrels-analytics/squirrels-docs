import pytest
from unittest.mock import MagicMock, patch
import json
import io

from squirrels._auth import Authenticator, AuthProviderArgs
from squirrels._schemas.auth_models import CustomUserFields, ProviderConfigs, AuthProvider, RegisteredUser
from squirrels._env_vars import SquirrelsEnvVars
from squirrels import _utils as u, _constants as c

class MockCustomUserFields(CustomUserFields):
    pass

@pytest.fixture
def env_vars_unformatted():
    return {
        c.SQRL_SECRET_KEY: "test_secret_key"
    }

@pytest.fixture
def env_vars():
    return SquirrelsEnvVars(
        project_path=".",
        SQRL_SECRET__KEY="test_secret_key"
    )

def test_external_only_skips_db_init(env_vars, env_vars_unformatted):
    logger = u.Logger("")
    auth_args = AuthProviderArgs(project_path=".", proj_vars={}, env_vars=env_vars_unformatted)
    auth_instance = Authenticator(
        logger, env_vars, auth_args, provider_functions=[], custom_user_fields_cls=MockCustomUserFields, external_only=True
    )
    
    # Check that engine and Session are not initialized
    assert not hasattr(auth_instance, "engine")
    assert not hasattr(auth_instance, "Session")
    
    auth_instance.close()

def test_get_user_from_external_token(env_vars, env_vars_unformatted):
    logger = u.Logger("")
    
    def mock_get_user(payload):
        return RegisteredUser(username=payload["sub"], access_level="member", custom_fields=MockCustomUserFields())
    
    provider_configs = ProviderConfigs(
        client_id="client_id",
        client_secret="client_secret",
        server_url="https://auth.example.com",
        get_user=mock_get_user
    )
    provider = AuthProvider(name="test_provider", label="Test Provider", icon="", provider_configs=provider_configs)
    
    auth_args = AuthProviderArgs(project_path=".", proj_vars={}, env_vars=env_vars_unformatted)
    auth_instance = Authenticator(
        logger, env_vars, auth_args, provider_functions=[], custom_user_fields_cls=MockCustomUserFields, external_only=True
    )
    auth_instance.auth_providers = [provider]
    
    metadata = {
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"]
    }
    
    with patch("requests.get") as MockGet, \
         patch("squirrels._auth.PyJWKClient") as MockJWKClient, \
         patch("jwt.decode") as MockJWTDecode:
        
        mock_response = MagicMock()
        mock_response.json.return_value = metadata
        MockGet.return_value = mock_response
        
        mock_jwks_client = MagicMock()
        MockJWKClient.return_value = mock_jwks_client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "public_key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        MockJWTDecode.return_value = {"sub": "test_user", "exp": 1234567890.0}
        
        token = "header.payload.signature"
        user, expiry = auth_instance.get_user_from_external_token(token, "test_provider")
        
        assert user.username == "test_user"
        assert expiry == 1234567890.0
        MockJWTDecode.assert_called_once_with(
            token,
            key="public_key",
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )

def test_get_user_from_external_token_auto_lookup(env_vars, env_vars_unformatted):
    logger = u.Logger("")
    
    def mock_get_user(payload):
        return RegisteredUser(username=payload["sub"], access_level="member", custom_fields=MockCustomUserFields())
    
    provider_configs = ProviderConfigs(
        client_id="client_id",
        client_secret="client_secret",
        server_url="https://auth.example.com",
        get_user=mock_get_user
    )
    provider = AuthProvider(name="test_provider", label="Test Provider", icon="", provider_configs=provider_configs)
    
    auth_args = AuthProviderArgs(project_path=".", proj_vars={}, env_vars=env_vars_unformatted)
    auth_instance = Authenticator(
        logger, env_vars, auth_args, provider_functions=[], custom_user_fields_cls=MockCustomUserFields, external_only=True
    )
    auth_instance.auth_providers = [provider]
    
    # Fake token with issuer payload
    import base64
    payload = json.dumps({"iss": "https://auth.example.com", "sub": "test_user"}).encode()
    payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip('=')
    fake_token = f"header.{payload_b64}.signature"
    
    metadata = {
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"]
    }
    
    with patch("requests.get") as MockGet, \
         patch("squirrels._auth.PyJWKClient") as MockJWKClient, \
         patch("jwt.decode") as MockJWTDecode:
        
        mock_response = MagicMock()
        mock_response.json.return_value = metadata
        MockGet.return_value = mock_response
        
        mock_jwks_client = MagicMock()
        MockJWKClient.return_value = mock_jwks_client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "public_key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        MockJWTDecode.return_value = {"iss": "https://auth.example.com", "sub": "test_user", "exp": 1234567890.0}
        
        # Call without provider_name
        user, expiry = auth_instance.get_user_from_external_token(fake_token)
        
        assert user.username == "test_user"
        assert expiry == 1234567890.0
        MockJWTDecode.assert_called_once()

def test_get_user_from_external_token_fetches_metadata(env_vars, env_vars_unformatted):
    logger = u.Logger("")
    
    def mock_get_user(payload):
        return RegisteredUser(username=payload["sub"], access_level="member", custom_fields=MockCustomUserFields())
    
    provider_configs = ProviderConfigs(
        client_id="client_id",
        client_secret="client_secret",
        server_url="https://auth.example.com",
        get_user=mock_get_user
    )
    provider = AuthProvider(name="test_provider", label="Test Provider", icon="", provider_configs=provider_configs)
    
    auth_args = AuthProviderArgs(project_path=".", proj_vars={}, env_vars=env_vars_unformatted)
    auth_instance = Authenticator(
        logger, env_vars, auth_args, provider_functions=[], custom_user_fields_cls=MockCustomUserFields, external_only=True
    )
    auth_instance.auth_providers = [provider]
    
    metadata = {
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256", "ES256"]
    }
    
    with patch("requests.get") as MockGet, \
         patch("squirrels._auth.PyJWKClient") as MockJWKClient, \
         patch("jwt.decode") as MockJWTDecode:
        
        mock_response = MagicMock()
        mock_response.json.return_value = metadata
        MockGet.return_value = mock_response
        
        mock_jwks_client = MagicMock()
        MockJWKClient.return_value = mock_jwks_client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "public_key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key
        
        MockJWTDecode.return_value = {"sub": "test_user", "exp": 1234567890.0}
        
        token = "header.payload.signature"
        user, expiry = auth_instance.get_user_from_external_token(token, "test_provider")
        
        assert user.username == "test_user"
        assert expiry == 1234567890.0
        MockGet.assert_called_once_with(provider_configs.server_metadata_url)
        MockJWTDecode.assert_called_once_with(
            token,
            key="public_key",
            algorithms=["RS256", "ES256"],
            options={"verify_aud": False, "verify_iss": False},
        )
