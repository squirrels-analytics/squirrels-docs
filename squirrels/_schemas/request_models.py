from pydantic import BaseModel, Field, field_validator


class McpRequestHeaders(BaseModel):
    raw_headers: dict[str, str] = Field(default_factory=dict, description="The raw HTTP headers")

    @field_validator("raw_headers")
    @classmethod
    def lowercase_keys(cls, v: dict[str, str]) -> dict[str, str]:
        return {key.lower(): val for key, val in v.items()}

    @property
    def bearer_token(self) -> str | None:
        auth_header = self.raw_headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        return None

    @property
    def api_key(self) -> str | None:
        return self.raw_headers.get("x-api-key")

    @property
    def feature_flags(self) -> set[str]:
        feature_flags_str = self.raw_headers.get("x-feature-flags", "")
        return set(x.strip() for x in feature_flags_str.split(",") if x.strip())
