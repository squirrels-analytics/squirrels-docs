from typing import Literal
from squirrels.auth import CustomUserFields as BaseCustomUserFields, ProviderConfigs, RegisteredUser, provider
from squirrels.arguments import AuthProviderArgs


class CustomUserFields(BaseCustomUserFields):
    """
    Extend the CustomUserFields class to add custom user attributes. 
    - Only the following types are supported: [str, int, float, bool, typing.Literal]
    - Add "| None" after the type to make it nullable. 
    - Always set a default value for the field (use None if default is null).
    
    Example:
        organization: str | None = None
    """
    role: Literal["manager", "staff", "customer"] = "staff"


# @provider(
#     name="google", label="Google", 
#     icon="https://www.google.com/favicon.ico"
#     # ^ Note: You also can save the google favicon as an image file in "resources/public/logos/google.ico" 
#     #   and use icon="/public/logos/google.ico" instead
# )
def google_auth_provider(sqrl: AuthProviderArgs) -> ProviderConfigs:
    """
    Example provider configs for authenticating a user using Google credentials.

    See the following page for setting up the CLIENT_ID and CLIENT_SECRET for Google specifically: 
    - https://support.google.com/googleapi/answer/6158849?hl=en

    IMPORTANT: Avoid using Google OAuth if you set auth_strategy to 'external'.
    - If auth_strategy is 'external', MCP clients would require Dynamic Client Registration (DCR) to 
      authenticate with the associated OAuth provider used by the Squirrels MCP server.
    - Unfortunately, Google OAuth (and many other OAuth providers) do not support DCR. If auth_strategy 
      is 'external', consider using an alternative that supports DCR instead (such as WorkOS or Keycloak).
    """
    def get_sqrl_user(claims: dict) -> RegisteredUser:
        custom_fields = CustomUserFields(role="customer")
        return RegisteredUser(
            username=claims["email"],
            access_level="member", # or "admin"
            custom_fields=custom_fields
        )

    # TODO: Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to the .env file
    # Then, uncomment the @provider decorator above and set the client_id and client_secret below
    provider_configs = ProviderConfigs(
        client_id="", # sqrl.env_vars["GOOGLE_CLIENT_ID"],
        client_secret="", # sqrl.env_vars["GOOGLE_CLIENT_SECRET"],
        server_url="https://accounts.google.com",
        client_kwargs={"scope": "openid email profile"},
        get_user=get_sqrl_user
    )

    return provider_configs
