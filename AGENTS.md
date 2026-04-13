# FieldKit MCP - Agent Guide

This document provides essential information for agents working with the FieldKit MCP codebase.

## Project Overview

FieldKit MCP is a single-file Python MCP (Model Context Protocol) server that exposes offensive security reconnaissance tools for LLM-driven security assessments. It wraps multiple popular CLI tools and provides Google Dorking query building capabilities.

### Architecture

- **Single-file design**: All server logic in `fieldkit_mcp_server.py`
- **HTTP transport**: Runs as streamable HTTP server (default port 8000)
- **Tool wrapping**: Exposes recon tools via standardized MCP interface
- **Mixed safety**: Combines passive OSINT with active scanning tools

## Prerequisites & Setup

### Essential Commands

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Go-based recon tools (must be on PATH)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install Python-based tool
pip install theHarvester

# Run the server (default port 8000)
python fieldkit_mcp_server.py

# Run on custom port
python fieldkit_mcp_server.py --port 9000

# Or via environment variable
FIELDKIT_MCP_PORT=9000 python fieldkit_mcp_server.py
```

### Environment Variables (Optional but Recommended)

These enhance passive source coverage:

```bash
export SHODAN_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export CHAOS_API_KEY="..."
export GITHUB_TOKEN="..."
```

## Code Organization

### File Structure
```
fieldkit-mcp/
├── README.md              # User documentation
├── requirements.txt       # Python dependencies  
├── fieldkit_mcp_server.py # Complete server implementation
└── AGENTS.md             # This file
```

### Server Structure

The single Python file is organized into these sections:

1. **Imports & Constants** (lines 31-62)
   - Core dependencies: `mcp`, `pydantic`, `asyncio`
   - Configuration constants: `DEFAULT_TIMEOUT`, `MAX_OUTPUT_LINES`, `SERVER_PORT`

2. **Shared Models** (lines 69-73)
   - `ResponseFormat` enum: `MARKDOWN` or `JSON`

3. **Shared Helpers** (lines 79-183)
   - `_check_binary()`: Verifies required tools exist on PATH
   - `_run_command()`: Async subprocess execution with timeout
   - `_truncate_output()`: Limits output to prevent context overflow
   - `_format_result()`: Unified result formatting (markdown/JSON)

4. **Tool Implementations** (lines 187-1090)
   - Each tool has: Pydantic input model, `@mcp.tool()` decorator, async function
   - Standardized error handling via `_check_binary()`
   - Consistent result formatting via `_format_result()`

5. **Entry Point** (lines 1096-1104)
   - argparse for port configuration
   - HTTP transport startup

## Tool Specifications

### Available Tools

| MCP Tool | Wraps | Type | Description |
|----------|-------|------|-------------|
| `recon_google_dork` | — | Passive | Builds Google dork queries (presets + manual operators) |
| `recon_subfinder` | `subfinder` | Passive | Subdomain enumeration via passive sources |
| `recon_nuclei` | `nuclei` | **Active** | Vulnerability scanning with templates |
| `recon_dnsx` | `dnsx` | Passive | DNS resolution & record enumeration |
| `recon_katana` | `katana` | **Active** | Web crawling / endpoint discovery |
| `recon_theharvester` | `theHarvester` | Passive | Email, subdomain & IP OSINT |
| `recon_status` | — | Local | Checks which binaries and API keys are available |

### Input Model Patterns

All tool inputs follow these patterns:

```python
class ToolInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    
    # Required field
    target: str = Field(..., description="Target description")
    
    # Optional fields with defaults
    timeout: int = Field(default=DEFAULT_TIMEOUT, ge=30, le=1800)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
    
    @field_validator
    @classmethod
    def validate_field(cls, v: str) -> str:
        # Validation logic
        return processed_value
```

### Output Patterns

All tools return formatted strings:

```python
# Markdown format (default)
## Tool Results
```
output content
```

### Stderr
```
error messages
```

# JSON format
{
  "stdout": "output content",
  "stderr": "error messages", 
  "returncode": 0,
  "timed_out": false
}
```

## Coding Conventions

### Naming Patterns

- **Function names**: `snake_case` with tool prefix (`recon_` for tool functions, `_` for helpers)
- **Classes**: `PascalCase` with descriptive suffix (`Input`, `Model`, `Format`)
- **Constants**: `UPPER_SNAKE_CASE` with underscores
- **Variables**: `snake_case`, descriptive names
- **Enums**: `PascalCase` with string values

### Error Handling Patterns

```python
# Binary availability check
_check_binary("toolname")  # Raises FileNotFoundError if missing

# Command execution with timeout
result = await _run_command(cmd, timeout=timeout)

# Consistent error formatting
if not required_param:
    return "Error: Provide required_param."
```

### Pydantic Models

- Always use `ConfigDict(str_strip_whitespace=True, extra="forbid")`
- Include field descriptions for LLM context
- Use validators for input sanitization (domain cleaning, etc.)
- Set reasonable min/max bounds on numeric fields

### Async Patterns

- All tool functions are `async def`
- Use `asyncio.create_subprocess_exec()` for command execution
- Always handle timeouts with `asyncio.wait_for()`
- Process output with `await proc.communicate()`

## Important Gotchas

### Security Considerations

⚠️ **Authorization Required**: Tools marked **Active** (nuclei, katana) send requests to targets. Only use against systems you have explicit written authorization to test.

- **Active tools**: `recon_nuclei`, `recon_katana` - send HTTP requests
- **Passive tools**: `recon_google_dork`, `recon_subfinder`, `recon_dnsx`, `recon_theharvester` - no direct target traffic

### Google ToS Compliance

The Google Dorking tool **only builds queries** - it does NOT execute searches to avoid violating Google's Terms of Service. LLMs must instruct users to copy queries into a browser.

### Binary Dependencies

All wrapped tools must be installed separately and available on PATH:
- Use `recon_status` tool to check availability before using other tools
- Missing binaries raise `FileNotFoundError` with clear install instructions
- Both Go-based and Python-based tools required

### Output Management

- `MAX_OUTPUT_LINES = 500` prevents context overflow
- Long outputs are truncated with notice: `[... truncated - X additional lines omitted]`
- Use `response_format: "json"` for machine-readable output

### Timeout Handling

- `DEFAULT_TIMEOUT = 300` seconds (nuclei scans can be slow)
- Individual tools can override timeout (ge=30, le=1800 typical range)
- Timeout returns: `{"timed_out": True, "stderr": "Command timed out after Xs"}`

## Testing Approach

### Manual Testing

```bash
# Check environment
python fieldkit_mcp_server.py --help

# Test server startup
python fieldkit_mcp_server.py --port 8000 &

# Test tool availability
# (Connect MCP client and call recon_status)
```

### Integration Testing

- Test each tool individually via MCP client
- Verify binary dependencies with `recon_status`
- Test both markdown and JSON output formats
- Test timeout behavior with slow operations
- Test error handling for missing binaries/invalid inputs

### Development Workflow

1. **Add new tool**:
   - Create Pydantic input model with validation
   - Implement async function with `_check_binary()` call
   - Use `_run_command()` for execution
   - Return formatted result with `_format_result()`

2. **Test changes**:
   - Restart server with new code
   - Call `recon_status` to verify environment
   - Test new tool with various inputs
   - Verify error handling works

## Common Patterns

### Adding New Recon Tools

```python
class NewToolInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    
    target: str = Field(..., description="Target description")
    timeout: int = Field(default=DEFAULT_TIMEOUT, ge=30, le=600)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)

@mcp.tool(
    name="recon_newtool",
    annotations={
        "title": "New Tool — Description",
        "readOnlyHint": True,  # or False for active tools
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_newtool(params: NewToolInput) -> str:
    """Tool description and usage guidance."""
    
    _check_binary("newtool")
    
    cmd = ["newtool", "-silent", "-target", params.target]
    result = await _run_command(cmd, timeout=params.timeout)
    
    return _format_result(result, "newtool", params.response_format)
```

### Bulk Operations

Many tools support stdin for bulk processing:

```python
# Single target
if not params.target_list_stdin:
    cmd.extend(["-u", params.target])

# Bulk targets via stdin
result = await _run_command(
    cmd, 
    timeout=params.timeout,
    stdin_data=params.target_list_stdin if params.target_list_stdin else None
)
```

## Configuration

### Server Configuration

- **Port**: `FIELDKIT_MCP_PORT` environment variable or `--port` argument
- **Logging**: stderr only (stdout reserved for MCP transport)
- **Timeouts**: Configurable per tool with sensible defaults

### MCP Client Configuration

```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **"Binary not found on PATH"**:
   - Install required tools via `go install` or `pip`
   - Verify installation location is in system PATH
   - Use `recon_status` to check tool availability

2. **Command timeouts**:
   - Increase timeout parameter for long-running scans
   - Reduce nuclei concurrency for slow targets
   - Use severity filters to limit scope

3. **API key issues**:
   - Set environment variables for enhanced results
   - Verify keys are valid and have necessary permissions
   - Check source-specific requirements

### Debug Logging

Server logs to stderr with format: `YYYY-MM-DD HH:MM:SS [LEVEL] logger: message`

```python
import logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("fieldkit_mcp")
```

## Memory Considerations

- Large outputs are automatically truncated to 500 lines
- Bulk operations should use reasonable limits
- DNS brute-forcing can generate significant results - use max_results parameter
- Nuclei scans can be memory intensive with many concurrent templates

This guide should help agents understand the codebase structure, patterns, and conventions for effective development and maintenance of the FieldKit MCP server.
