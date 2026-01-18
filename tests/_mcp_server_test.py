"""
Unit tests for the MCP server implementation.

Tests the low-level MCP Server handlers for list_tools, list_resources, 
call_tool, and read_resource.
"""
from __future__ import annotations

from mcp.types import CallToolResult
from pydantic import AnyUrl
from starlette.testclient import TestClient
from fastapi import FastAPI
import polars as pl
import json
import pytest

from squirrels._dataset_types import DatasetResult, ModelConfig
from squirrels._exceptions import InvalidInputError
from squirrels._http_error_responses import invalid_input_error_to_json_response
from squirrels._mcp_server import McpServerBuilder
from squirrels._schemas.auth_models import RegisteredUser, CustomUserFields
from squirrels._schemas import response_models as rm


@pytest.fixture
def mock_data_catalog():
    """Create a mock data catalog response."""
    return rm.CatalogModelForMcp(
        parameters=[],
        datasets=[]
    )


@pytest.fixture
def mock_parameters():
    """Create a mock parameters response."""
    return rm.ParametersModel(parameters=[])


@pytest.fixture
def mock_dataset_result():
    """Create a mock dataset result response."""
    return DatasetResult(target_model_config=ModelConfig(columns=[]), df=pl.DataFrame())


@pytest.fixture
def mcp_builder(mock_data_catalog, mock_parameters, mock_dataset_result) -> McpServerBuilder:
    """Create an McpServerBuilder with mocked functions."""
    async def get_data_catalog(user):
        return mock_data_catalog
    
    async def get_dataset_parameters(dataset, parameter_name, selected_ids, user):
        return mock_parameters
    
    async def get_dataset_results(dataset, parameters, sql_query, user, headers):
        return mock_dataset_result
    
    return McpServerBuilder(
        project_name="test_project",
        project_label="Test Project",
        max_rows_for_ai=100,
        get_user_from_headers=lambda api_key, bearer_token: (None, None),
        get_data_catalog_for_mcp=get_data_catalog,
        get_dataset_parameters_for_mcp=get_dataset_parameters,
        get_dataset_results_for_mcp=get_dataset_results,
    )


@pytest.fixture
def mcp_builder_enforced_auth(mock_data_catalog, mock_parameters, mock_dataset_result) -> McpServerBuilder:
    """MCP builder with OAuth enforcement enabled."""

    async def get_data_catalog(user):
        return mock_data_catalog

    async def get_dataset_parameters(dataset, parameter_name, selected_ids, user):
        return mock_parameters

    async def get_dataset_results(dataset, parameters, sql_query, user, headers):
        return mock_dataset_result

    def get_user_from_headers(api_key, bearer_token):
        if bearer_token == "good-token":
            return RegisteredUser(username="alice", custom_fields=CustomUserFields()), None
        raise InvalidInputError(401, "invalid_external_token", "Invalid external authorization token")

    return McpServerBuilder(
        project_name="test_project",
        project_label="Test Project",
        max_rows_for_ai=100,
        get_user_from_headers=get_user_from_headers,
        get_data_catalog_for_mcp=get_data_catalog,
        get_dataset_parameters_for_mcp=get_dataset_parameters,
        get_dataset_results_for_mcp=get_dataset_results,
        enforce_oauth_bearer=True,
        oauth_resource_metadata_path="/.well-known/oauth-protected-resource",
    )


class TestListTools:
    """Tests for the list_tools handler."""
    
    @pytest.mark.anyio
    async def test_list_tools_returns_three_tools(self, mcp_builder: McpServerBuilder):
        """Test that list_tools returns exactly three tools."""
        tools = await mcp_builder._list_tools()
        assert len(tools) == 3
    
    @pytest.mark.anyio
    async def test_list_tools_contains_catalog_tool(self, mcp_builder: McpServerBuilder):
        """Test that list_tools includes the data catalog tool."""
        tools = await mcp_builder._list_tools()
        tool_names = [t.name for t in tools]
        assert "get_data_catalog_from_test_project" in tool_names
    
    @pytest.mark.anyio
    async def test_list_tools_contains_parameters_tool(self, mcp_builder: McpServerBuilder):
        """Test that list_tools includes the dataset parameters tool."""
        tools = await mcp_builder._list_tools()
        tool_names = [t.name for t in tools]
        assert "get_dataset_parameters_from_test_project" in tool_names
    
    @pytest.mark.anyio
    async def test_list_tools_contains_results_tool(self, mcp_builder: McpServerBuilder):
        """Test that list_tools includes the dataset results tool."""
        tools = await mcp_builder._list_tools()
        tool_names = [t.name for t in tools]
        assert "get_dataset_results_from_test_project" in tool_names


class TestListResources:
    """Tests for the list_resources handler."""
    
    @pytest.mark.anyio
    async def test_list_resources_returns_one_resource(self, mcp_builder: McpServerBuilder):
        """Test that list_resources returns exactly one resource."""
        resources = await mcp_builder._list_resources()
        assert len(resources) == 1
    
    @pytest.mark.anyio
    async def test_list_resources_contains_data_catalog(self, mcp_builder: McpServerBuilder):
        """Test that list_resources includes the data catalog resource."""
        resources = await mcp_builder._list_resources()
        resource_uris = [str(r.uri) for r in resources]
        assert "sqrl://data-catalog" in resource_uris


class TestCallTool:
    """Tests for the call_tool handler."""
    
    @pytest.mark.anyio
    async def test_call_unknown_tool_returns_error(self, mcp_builder: McpServerBuilder):
        """Test that calling an unknown tool returns a CallToolResult with isError=True."""
        result = await mcp_builder._call_tool("unknown_tool", {})
        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert len(result.content) == 1
        assert "Unknown tool" in result.content[0].text
    
    @pytest.mark.anyio
    async def test_call_catalog_tool_returns_structured_data(self, mcp_builder: McpServerBuilder):
        """Test that calling the catalog tool returns structured data (dict)."""
        result = await mcp_builder._call_tool(
            "get_data_catalog_from_test_project", {}
        )
        # Returns dict directly for structured output
        assert isinstance(result, CallToolResult)
        assert "parameters" in result.structuredContent
        assert "datasets" in result.structuredContent
    
    @pytest.mark.anyio
    async def test_call_results_tool_with_invalid_limit_returns_error(self, mcp_builder: McpServerBuilder):
        """Test that calling results tool with limit > max returns error."""
        result = await mcp_builder._call_tool(
            "get_dataset_results_from_test_project",
            {
                "dataset": "test_dataset",
                "parameters": "{}",
                "limit": 1000  # Exceeds max_rows_for_ai=100
            }
        )
        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert len(result.content) == 1
        assert "Error" in result.content[0].text
        assert "100" in result.content[0].text


class TestReadResource:
    """Tests for the read_resource handler."""
    
    @pytest.mark.anyio
    async def test_read_catalog_resource_returns_json(self, mcp_builder: McpServerBuilder):
        """Test that reading the catalog resource returns JSON."""
        result = await mcp_builder._read_resource(AnyUrl("sqrl://data-catalog"))
        # Should be valid JSON string
        parsed = json.loads(result)
        assert "parameters" in parsed
        assert "datasets" in parsed
    
    @pytest.mark.anyio
    async def test_read_unknown_resource_raises_error(self, mcp_builder: McpServerBuilder):
        """Test that reading an unknown resource raises an error."""
        with pytest.raises(ValueError, match="Unknown resource URI"):
            await mcp_builder._read_resource(AnyUrl("sqrl://unknown"))


class TestMcpHttpAuthEnforcement:
    def test_mcp_missing_bearer_returns_401_with_www_authenticate(self, mcp_builder_enforced_auth: McpServerBuilder):
        app = mcp_builder_enforced_auth.get_asgi_app()
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 401
        assert resp.json()["error"] == "user_required"
        assert "WWW-Authenticate" in resp.headers
        assert "/.well-known/oauth-protected-resource" in resp.headers["WWW-Authenticate"]

    def test_mcp_invalid_bearer_returns_401(self, mcp_builder_enforced_auth: McpServerBuilder):
        app = mcp_builder_enforced_auth.get_asgi_app()
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": "Bearer bad-token"})
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_external_token"

    def test_mcp_no_enforcement_does_not_force_401(self, mcp_builder: McpServerBuilder):
        app = mcp_builder.get_asgi_app()
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code != 401


class TestApiV0WwwAuthenticatePointsToTopLevel:
    def test_api_v0_401_points_to_top_level_resource_metadata(self):
        """
        Minimal regression test: a 401 generated inside a sub-app mounted at `/api/0`
        should reference a top-level `/.well-known/oauth-protected-resource` URL (no `/api/0` prefix).
        """
        api_v0_mount_path = "/api/0"

        app = FastAPI()
        subapp = FastAPI()

        @subapp.middleware("http")
        async def catch_invalid_input(request, call_next):
            try:
                return await call_next(request)
            except InvalidInputError as exc:
                return invalid_input_error_to_json_response(
                    request,
                    exc,
                    oauth_resource_metadata_path="/.well-known/oauth-protected-resource",
                    strip_path_suffix=api_v0_mount_path,
                )

        @subapp.get("/needs-auth")
        async def needs_auth():
            raise InvalidInputError(401, "user_required", "Authentication is required")

        app.mount(api_v0_mount_path, subapp)

        client = TestClient(app)
        resp = client.get("/api/0/needs-auth")
        assert resp.status_code == 401
        header = resp.headers.get("WWW-Authenticate", "")
        assert "/.well-known/oauth-protected-resource" in header
        assert "/api/0/.well-known/oauth-protected-resource" not in header

