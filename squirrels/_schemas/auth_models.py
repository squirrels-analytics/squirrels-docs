from typing import Callable, Any, Literal
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_serializer


class CustomUserFields(BaseModel):
    """
    Extend this class to add custom user fields.
    - Only the following types are supported: [str, int, float, bool, typing.Literal]
    - Add "| None" after the type to make it nullable. 
    - Always set a default value for the column (use None if default is null).
    """
    model_config = ConfigDict(extra='allow')


class AbstractUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    access_level: Literal["admin", "member", "guest"]
    custom_fields: CustomUserFields
    
    def __hash__(self):
        return hash(self.username)
    
    def __str__(self):
        return self.username


class GuestUser(AbstractUser):
    access_level: Literal["guest"] = "guest"


class RegisteredUser(AbstractUser):
    access_level: Literal["admin", "member"] = "member"


class ApiKey(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    last_four: str
    title: str
    username: str
    created_at: datetime
    expires_at: datetime
    
    @field_serializer('created_at', 'expires_at')
    def serialize_datetime(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class UserField(BaseModel):
    name: str = Field(description="The name of the field")
    label: str = Field(description="The human-friendly display name for the field")
    type: str = Field(description="The type of the field")
    nullable: bool = Field(description="Whether the field is nullable")
    enum: list[str] | None = Field(description="The possible values of the field (or None if not applicable)")
    default: Any | None = Field(description="The default value of the field (or None if field is required)")


class UserFieldsModel(BaseModel):
    username: UserField = Field(description="The username field metadata")
    access_level: UserField = Field(description="The access level field metadata")
    custom_fields: list[UserField] = Field(description="The list of custom user fields metadata for the current Squirrels project")


class ProviderConfigs(BaseModel):
    client_id: str
    client_secret: str
    server_url: str
    server_metadata_path: str = Field(default="/.well-known/oauth-authorization-server")
    client_kwargs: dict = Field(default_factory=dict)
    get_user: Callable[[dict], RegisteredUser]

    @property
    def server_metadata_url(self) -> str:
        return f"{self.server_url}{self.server_metadata_path}"


class AuthProvider(BaseModel):
    name: str = Field(description="The name of the provider")
    label: str = Field(description="The human-friendly display name for the provider")
    icon: str = Field(description="The URL of the provider's icon. Can also start with '/public/' to indicate a file in the '/resources/public/' directory.")
    provider_configs: ProviderConfigs
