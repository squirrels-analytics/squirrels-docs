import pytest
from unittest.mock import MagicMock, patch

from squirrels._auth import Authenticator, AuthProviderArgs
from squirrels._schemas.auth_models import CustomUserFields, ProviderConfigs, AuthProvider, RegisteredUser
from squirrels._env_vars import SquirrelsEnvVars
from squirrels._exceptions import InvalidInputError
from squirrels import _utils as u, _constants as c


class MockCustomUserFields(CustomUserFields):
    pass


@pytest.fixture
def env_vars_unformatted():
    return {
        c.SQRL_SECRET_KEY: "test_secret_key",
    }


@pytest.fixture
def env_vars():
    return SquirrelsEnvVars(
        project_path=".",
        SQRL_SECRET__KEY="test_secret_key",
    )


def _make_auth_instance(env_vars, env_vars_unformatted) -> Authenticator:
    logger = u.Logger("")
    auth_args = AuthProviderArgs(project_path=".", proj_vars={}, env_vars=env_vars_unformatted)
    auth_instance = Authenticator(
        logger,
        env_vars,
        auth_args,
        provider_functions=[],
        custom_user_fields_cls=MockCustomUserFields,
        external_only=True,
    )

    def mock_get_user(payload: dict) -> RegisteredUser:
        return RegisteredUser(username=payload.get("sub", "u"), access_level="member", custom_fields=MockCustomUserFields())

    provider_configs = ProviderConfigs(
        client_id="client_id",
        client_secret="client_secret",
        server_url="https://auth.example.com",
        get_user=mock_get_user,
    )
    provider = AuthProvider(name="test_provider", label="Test Provider", icon="", provider_configs=provider_configs)
    auth_instance.auth_providers = [provider]
    return auth_instance


def test_get_user_info_from_token_details_prefers_userinfo_field(env_vars, env_vars_unformatted):
    auth_instance = _make_auth_instance(env_vars, env_vars_unformatted)
    token_details = {"userinfo": {"email": "a@example.com"}}
    assert auth_instance.get_user_info_from_token_details("test_provider", token_details) == {"email": "a@example.com"}


def test_get_user_info_from_token_details_verifies_id_token_and_nonce(env_vars, env_vars_unformatted):
    auth_instance = _make_auth_instance(env_vars, env_vars_unformatted)

    token_details = {"id_token": "header.payload.signature", "access_token": "opaque"}
    metadata = {
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "issuer": "https://auth.example.com",
        "id_token_signing_alg_values_supported": ["RS256"],
    }

    with patch("requests.get") as MockGet, patch("squirrels._auth.PyJWKClient") as MockJWKClient, patch("jwt.decode") as MockJWTDecode:
        mock_response = MagicMock()
        mock_response.json.return_value = metadata
        MockGet.return_value = mock_response

        mock_jwks_client = MagicMock()
        MockJWKClient.return_value = mock_jwks_client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "public_key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        MockJWTDecode.return_value = {"iss": "https://auth.example.com", "sub": "test_user", "nonce": "n"}

        user_info = auth_instance.get_user_info_from_token_details("test_provider", token_details, expected_nonce="n")
        assert user_info["sub"] == "test_user"

        MockJWTDecode.assert_called_once_with(
            "header.payload.signature",
            key="public_key",
            algorithms=["RS256"],
            audience="client_id",
            options={"verify_aud": True, "verify_iss": False},
        )


def test_get_user_info_from_token_details_nonce_mismatch_raises(env_vars, env_vars_unformatted):
    auth_instance = _make_auth_instance(env_vars, env_vars_unformatted)

    token_details = {"id_token": "header.payload.signature", "access_token": "opaque"}
    metadata = {
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "issuer": "https://auth.example.com",
        "id_token_signing_alg_values_supported": ["RS256"],
    }

    with patch("requests.get") as MockGet, patch("squirrels._auth.PyJWKClient") as MockJWKClient, patch("jwt.decode") as MockJWTDecode:
        mock_response = MagicMock()
        mock_response.json.return_value = metadata
        MockGet.return_value = mock_response

        mock_jwks_client = MagicMock()
        MockJWKClient.return_value = mock_jwks_client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "public_key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        MockJWTDecode.return_value = {"iss": "https://auth.example.com", "sub": "test_user", "nonce": "x"}

        with pytest.raises(InvalidInputError) as exc:
            auth_instance.get_user_info_from_token_details("test_provider", token_details, expected_nonce="y")

        assert exc.value.status_code == 401

