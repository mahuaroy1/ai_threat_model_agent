"""Knowledge base of LangChain / LangGraph APIs and dangerous Python sinks.

Keeping these lists in one module makes the analyzer easy to extend: adding
support for a new tool, loader, or provider is usually a one-line change.
"""

from __future__ import annotations

from enum import Enum

from .models import Severity

AI_FRAMEWORK_PREFIXES: tuple[str, ...] = ("langchain", "langgraph", "langserve", "langsmith")


def is_ai_framework(qualified_name: str) -> bool:
    """True if a resolved import path belongs to LangChain, LangGraph, or friends."""
    return qualified_name.startswith(AI_FRAMEWORK_PREFIXES)


def framework_of(qualified_name: str) -> str | None:
    if qualified_name.startswith("langgraph"):
        return "LangGraph"
    if qualified_name.startswith(("langchain", "langserve", "langsmith")):
        return "LangChain"
    return None


# --------------------------------------------------------------------------- models

MODEL_CLASSES = frozenset(
    {
        "OpenAI", "AzureOpenAI", "Ollama", "OllamaLLM", "HuggingFaceEndpoint",
        "HuggingFacePipeline", "HuggingFaceHub", "Bedrock", "BedrockLLM", "VertexAI",
        "LlamaCpp", "Cohere", "Replicate", "GPT4All", "init_chat_model",
    }
)

# (keyword in lower-cased qualified name, provider label, runs locally)
_PROVIDER_HINTS: tuple[tuple[str, str, bool], ...] = (
    ("ollama", "ollama", True),
    ("llamacpp", "llama.cpp", True),
    ("llama_cpp", "llama.cpp", True),
    ("gpt4all", "gpt4all", True),
    ("huggingfacepipeline", "huggingface-local", True),
    ("azure", "azure-openai", False),
    ("openai", "openai", False),
    ("anthropic", "anthropic", False),
    ("vertex", "google", False),
    ("google", "google", False),
    ("gemini", "google", False),
    ("bedrock", "aws-bedrock", False),
    ("aws", "aws-bedrock", False),
    ("mistral", "mistral", False),
    ("groq", "groq", False),
    ("cohere", "cohere", False),
    ("fireworks", "fireworks", False),
    ("together", "together", False),
    ("deepseek", "deepseek", False),
    ("xai", "xai", False),
    ("huggingface", "huggingface", False),
)

LOCAL_PROVIDERS = frozenset(provider for _, provider, local in _PROVIDER_HINTS if local)


def is_model_class(simple_name: str) -> bool:
    return simple_name in MODEL_CLASSES or (
        simple_name.startswith("Chat") and len(simple_name) > 4 and simple_name[4].isupper()
    )


def provider_for(hint: str) -> tuple[str, bool]:
    """Infer ``(provider, is_local)`` from a qualified name or ``provider:model`` string."""
    lowered = hint.lower()
    for keyword, provider, local in _PROVIDER_HINTS:
        if keyword in lowered:
            return provider, local
    return "unknown", False


# --------------------------------------------------------------------------- tools

# Built-in tools that hand the model a broad capability, with the reason.
DANGEROUS_TOOLS: dict[str, tuple[Severity, str]] = {
    "ShellTool": (Severity.CRITICAL, "arbitrary shell command execution"),
    "BashProcess": (Severity.CRITICAL, "arbitrary shell command execution"),
    "PythonREPLTool": (Severity.CRITICAL, "arbitrary Python code execution"),
    "PythonAstREPLTool": (Severity.CRITICAL, "arbitrary Python code execution"),
    "PythonREPL": (Severity.CRITICAL, "arbitrary Python code execution"),
    "create_python_agent": (Severity.CRITICAL, "agent with arbitrary Python code execution"),
    "create_pandas_dataframe_agent": (Severity.CRITICAL, "agent that executes generated Python"),
    "create_csv_agent": (Severity.CRITICAL, "agent that executes generated Python"),
    "create_spark_dataframe_agent": (Severity.CRITICAL, "agent that executes generated Python"),
    "FileManagementToolkit": (Severity.HIGH, "read/write/delete access to the file system"),
    "WriteFileTool": (Severity.HIGH, "file system writes"),
    "DeleteFileTool": (Severity.HIGH, "file deletion"),
    "MoveFileTool": (Severity.HIGH, "file moves/overwrites"),
    "CopyFileTool": (Severity.MEDIUM, "file copies/overwrites"),
    "RequestsToolkit": (Severity.HIGH, "arbitrary HTTP requests (SSRF, data exfiltration)"),
    "RequestsGetTool": (Severity.HIGH, "arbitrary HTTP GET requests (SSRF, data exfiltration)"),
    "RequestsPostTool": (Severity.HIGH, "arbitrary HTTP POST requests"),
    "RequestsPutTool": (Severity.HIGH, "arbitrary HTTP PUT requests"),
    "RequestsPatchTool": (Severity.HIGH, "arbitrary HTTP PATCH requests"),
    "RequestsDeleteTool": (Severity.HIGH, "arbitrary HTTP DELETE requests"),
    "SQLDatabaseToolkit": (Severity.HIGH, "model-written SQL against a database"),
    "QuerySQLDataBaseTool": (Severity.HIGH, "model-written SQL against a database"),
    "QuerySQLDatabaseTool": (Severity.HIGH, "model-written SQL against a database"),
    "create_sql_agent": (Severity.HIGH, "agent that writes and runs SQL"),
    "PlayWrightBrowserToolkit": (Severity.HIGH, "autonomous web browsing"),
    "GmailToolkit": (Severity.HIGH, "reading and sending email"),
    "GmailSendMessage": (Severity.HIGH, "sending email"),
    "SlackToolkit": (Severity.MEDIUM, "reading and posting Slack messages"),
    "GitHubToolkit": (Severity.HIGH, "repository write access"),
    "JiraToolkit": (Severity.MEDIUM, "ticket creation and modification"),
    "ZapierToolkit": (Severity.HIGH, "arbitrary third-party actions"),
}

# Tool names accepted by ``load_tools([...])`` that grant dangerous capabilities.
DANGEROUS_LOAD_TOOLS = frozenset(
    {"terminal", "shell", "python_repl", "requests", "requests_all", "requests_get",
     "requests_post", "requests_put", "requests_patch", "requests_delete"}
)

# Keyword arguments that disable framework guard rails when set to True.
DANGEROUS_FLAGS: dict[str, Severity] = {
    "allow_dangerous_code": Severity.CRITICAL,
    "allow_dangerous_requests": Severity.HIGH,
    "allow_dangerous_deserialization": Severity.HIGH,
    "allow_dangerous_tools": Severity.HIGH,
    "trust_remote_code": Severity.HIGH,
    "dangerously_allow_browser": Severity.MEDIUM,
}

# --------------------------------------------------------------------------- retrieval

WEB_CONTENT_SOURCES = frozenset(
    {
        "WebBaseLoader", "RecursiveUrlLoader", "SitemapLoader", "AsyncHtmlLoader",
        "AsyncChromiumLoader", "PlaywrightURLLoader", "SeleniumURLLoader", "UnstructuredURLLoader",
        "FireCrawlLoader", "TavilySearchResults", "TavilySearch", "TavilyExtract",
        "DuckDuckGoSearchRun", "DuckDuckGoSearchResults", "GoogleSearchAPIWrapper",
        "GoogleSearchRun", "GoogleSerperAPIWrapper", "SerpAPIWrapper", "BraveSearch",
        "WikipediaQueryRun", "WikipediaLoader", "ArxivQueryRun", "ArxivLoader",
        "YoutubeLoader", "GitHubIssuesLoader", "RequestsGetTool", "RequestsToolkit",
        "PlayWrightBrowserToolkit", "GmailToolkit", "SlackToolkit", "ConfluenceLoader",
        "NotionDBLoader",
    }
)

VECTOR_STORES = frozenset(
    {
        "Chroma", "FAISS", "PGVector", "Pinecone", "PineconeVectorStore", "Qdrant",
        "QdrantVectorStore", "Weaviate", "WeaviateVectorStore", "Milvus", "ElasticsearchStore",
        "InMemoryVectorStore", "MongoDBAtlasVectorSearch", "AzureSearch", "LanceDB",
        "OpenSearchVectorSearch", "RedisVectorStore", "Neo4jVector", "SupabaseVectorStore",
    }
)

DATABASE_SOURCES = frozenset({"SQLDatabase", "Neo4jGraph", "MongoDBChatMessageHistory"})

# --------------------------------------------------------------------------- agents

AGENT_FACTORIES = frozenset(
    {
        "create_react_agent", "create_tool_calling_agent", "create_openai_tools_agent",
        "create_openai_functions_agent", "create_structured_chat_agent", "create_json_chat_agent",
        "create_xml_agent", "create_agent", "AgentExecutor", "initialize_agent",
        "create_sql_agent", "create_pandas_dataframe_agent", "create_csv_agent",
        "create_supervisor", "create_swarm", "StateGraph", "MessageGraph", "ToolNode", "RemoteGraph",
    }
)
# Factories that make an application multi-agent (agents delegating to agents).
MULTI_AGENT_FACTORIES = frozenset({"create_supervisor", "create_swarm", "RemoteGraph", "create_handoff_tool"})


# Signals that a human approves actions before they run.
HUMAN_APPROVAL_CALLS = frozenset({"interrupt", "HumanInTheLoopMiddleware", "HumanApprovalCallbackHandler"})
HUMAN_APPROVAL_KWARGS = frozenset({"interrupt_before", "interrupt_after", "interrupt_on"})

# Calls that invoke a runnable (model, chain, agent, graph, or retriever).
INVOKE_METHODS = frozenset(
    {"invoke", "ainvoke", "stream", "astream", "batch", "abatch", "predict", "apredict",
     "run", "arun", "generate", "agenerate", "astream_events", "stream_events"}
)

# --------------------------------------------------------------------------- entry points

HTTP_ROUTE_DECORATORS = frozenset(
    {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket"}
)
CHAT_UI_HANDLERS = frozenset({"on_message", "on_chat_start"})  # Chainlit
STREAMLIT_INPUTS = frozenset({"chat_input", "text_input", "text_area", "file_uploader"})
GRADIO_INTERFACES = frozenset({"ChatInterface", "Interface"})
REQUEST_ATTRIBUTES = frozenset(
    {"json", "args", "form", "data", "values", "files", "body", "query_params",
     "path_params", "headers", "cookies", "get_json", "get_data"}
)
AUTH_HINT_WORDS = ("auth", "login", "token", "user", "jwt", "security", "verify",
                   "permission", "api_key", "apikey", "require", "protected", "session")

# --------------------------------------------------------------------------- dangerous sinks


class SinkKind(str, Enum):
    COMMAND = "command execution"
    CODE = "code execution"
    DESERIALIZATION = "unsafe deserialization"
    FILE_WRITE = "file write"
    FILE_DELETE = "file deletion"
    SQL = "SQL execution"
    NETWORK = "outbound network request"


_SINKS_BY_QUALIFIED_NAME: dict[str, SinkKind] = {
    **{name: SinkKind.COMMAND for name in (
        "os.system", "os.popen", "os.execv", "os.execvp", "os.execl", "os.spawnl",
        "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call",
        "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
        "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
    )},
    **{name: SinkKind.CODE for name in (
        "eval", "exec", "builtins.eval", "builtins.exec", "importlib.import_module", "__import__",
        "builtins.__import__", "runpy.run_path", "runpy.run_module",
    )},
    **{name: SinkKind.DESERIALIZATION for name in (
        "pickle.loads", "pickle.load", "dill.loads", "dill.load", "marshal.loads",
        "joblib.load", "torch.load", "yaml.unsafe_load", "shelve.open",
    )},
    **{name: SinkKind.FILE_DELETE for name in (
        "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree", "shutil.move",
        "os.rename", "os.replace",
    )},
    **{f"{module}.{method}": SinkKind.NETWORK
       for module in ("requests", "httpx")
       for method in ("get", "post", "put", "patch", "delete", "head", "request", "stream")},
    "urllib.request.urlopen": SinkKind.NETWORK,
    "urllib.request.Request": SinkKind.NETWORK,
}
_SINKS_BY_METHOD: dict[str, SinkKind] = {
    "execute": SinkKind.SQL,
    "executemany": SinkKind.SQL,
    "executescript": SinkKind.SQL,
    "exec_driver_sql": SinkKind.SQL,
    "write_text": SinkKind.FILE_WRITE,
    "write_bytes": SinkKind.FILE_WRITE,
    "unlink": SinkKind.FILE_DELETE,
    "rmdir": SinkKind.FILE_DELETE,
}

SINK_SEVERITY: dict[SinkKind, Severity] = {
    SinkKind.COMMAND: Severity.CRITICAL,
    SinkKind.CODE: Severity.CRITICAL,
    SinkKind.DESERIALIZATION: Severity.CRITICAL,
    SinkKind.SQL: Severity.HIGH,
    SinkKind.FILE_WRITE: Severity.HIGH,
    SinkKind.FILE_DELETE: Severity.HIGH,
    SinkKind.NETWORK: Severity.HIGH,
}

# Capabilities that make a tool "side-effecting" for human-approval checks.
SIDE_EFFECT_SINKS = frozenset(
    {SinkKind.COMMAND, SinkKind.CODE, SinkKind.FILE_WRITE, SinkKind.FILE_DELETE,
     SinkKind.SQL, SinkKind.NETWORK, SinkKind.DESERIALIZATION}
)


def classify_sink(qualified_name: str, method_name: str | None, open_mode: str | None) -> SinkKind | None:
    """Classify a call as a dangerous sink.

    Args:
        qualified_name: Import-resolved callee name, e.g. ``subprocess.run``.
        method_name: Attribute name when the call is ``obj.method(...)``.
        open_mode: Constant mode argument when the callee is ``open``.
    """
    if qualified_name in _SINKS_BY_QUALIFIED_NAME:
        return _SINKS_BY_QUALIFIED_NAME[qualified_name]
    if qualified_name in {"open", "builtins.open", "io.open"}:
        if open_mode and any(flag in open_mode for flag in "wax+"):
            return SinkKind.FILE_WRITE
        return None
    if method_name in _SINKS_BY_METHOD:
        return _SINKS_BY_METHOD[method_name]
    return None


# --------------------------------------------------------------------------- agent memory (ASI06)

# Memory/state classes and whether they persist across sessions ("long-term").
MEMORY_CLASSES: dict[str, str] = {
    **{name: "short-term (checkpointer)" for name in (
        "MemorySaver", "InMemorySaver", "SqliteSaver", "AsyncSqliteSaver", "PostgresSaver",
        "AsyncPostgresSaver", "RedisSaver", "AsyncRedisSaver", "MongoDBSaver",
    )},
    **{name: "long-term (store)" for name in (
        "InMemoryStore", "PostgresStore", "AsyncPostgresStore", "RedisStore", "AsyncRedisStore", "SqliteStore",
        "VectorStoreRetrieverMemory",
    )},
    **{name: "conversation history" for name in (
        "ConversationBufferMemory", "ConversationBufferWindowMemory", "ConversationSummaryMemory",
        "ConversationSummaryBufferMemory", "ConversationEntityMemory", "ChatMessageHistory",
        "InMemoryChatMessageHistory", "RedisChatMessageHistory", "SQLChatMessageHistory",
        "FileChatMessageHistory", "PostgresChatMessageHistory", "RunnableWithMessageHistory",
    )},
}

# Methods that persist content into memory that later sessions (or users) read back.
MEMORY_WRITE_METHODS = frozenset(
    {"add_documents", "aadd_documents", "add_texts", "aadd_texts", "from_documents", "afrom_documents",
     "from_texts", "afrom_texts", "save_context", "asave_context"}
)
# BaseStore methods; only matched when the receiver's name looks like a store.
STORE_WRITE_METHODS = frozenset({"put", "aput", "mset", "amset"})
STORE_SCOPED_METHODS = frozenset({"put", "aput", "get", "aget", "search", "asearch", "delete", "adelete"})
STORE_RECEIVER_HINTS = ("store", "memory", "memories")
# Keys in a RunnableConfig ``configurable`` dict that select whose memory is used.
MEMORY_SCOPE_KEYS = frozenset(
    {"thread_id", "user_id", "session_id", "conversation_id", "checkpoint_ns", "namespace", "tenant_id"}
)
# Expressions mentioning these are assumed to come from an authenticated identity.
AUTHENTICATED_IDENTITY_HINTS = (
    "current_user", "request.user", "auth", "principal", "identity", "claims", "jwt", "token", "g.user",
)

# --------------------------------------------------------------------------- identity (ASI03)

IDENTIFIER_PARAMETER_NAMES = frozenset(
    {"id", "user", "username", "email", "user_email", "account", "account_number", "customer",
     "tenant", "owner", "recipient", "patient", "employee"}
)
IDENTIFIER_PARAMETER_SUFFIXES = ("_id", "_ids", "_uuid", "_email", "_username", "_account")
# Annotations that hide a tool parameter from the model (the framework injects it).
INJECTED_ANNOTATION_HINTS = (
    "InjectedToolArg", "InjectedState", "InjectedStore", "InjectedToolCallId", "RunnableConfig", "ToolRuntime",
)


def is_identifier_parameter(name: str) -> bool:
    """True for tool parameters that name an object or identity, e.g. ``customer_id``."""
    lowered = name.lower()
    return lowered in IDENTIFIER_PARAMETER_NAMES or lowered.endswith(IDENTIFIER_PARAMETER_SUFFIXES)


# --------------------------------------------------------------------------- supply chain and MCP (ASI04, ASI07)

MCP_CLIENT_CLASSES = frozenset({"MultiServerMCPClient"})
MCP_TRANSPORT_FUNCTIONS = frozenset({"sse_client", "streamablehttp_client", "websocket_client"})
MCP_CONFIG_FILES = frozenset({"mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json"})
A2A_CLIENT_CLASSES = frozenset({"A2AClient", "A2ACardResolver"})
# Package runners that download and execute code at start-up.
PACKAGE_RUNNERS = frozenset({"npx", "uvx", "bunx", "pipx", "pnpx"})

# --------------------------------------------------------------------------- agent controls (ASI08-ASI10)

SIGNAL_HUMAN_APPROVAL = "human_approval"
SIGNAL_ITERATION_LIMIT = "iteration_limit"
SIGNAL_RATE_LIMIT = "rate_limit"
SIGNAL_AUDIT = "audit_trail"
SIGNAL_GUARDRAIL = "guardrail"
SIGNAL_STRUCTURED_OUTPUT = "structured_output"
SIGNAL_SANDBOX = "sandbox"
SIGNAL_MULTI_AGENT = "multi_agent"

ITERATION_LIMIT_KWARGS = frozenset({"max_iterations", "max_execution_time", "recursion_limit", "max_steps"})
UNBOUNDED_RECURSION_LIMIT = 1_000
RATE_LIMIT_NAMES = frozenset({"InMemoryRateLimiter", "Limiter", "RateLimiter"})
RATE_LIMIT_MODULES = ("slowapi", "flask_limiter", "fastapi_limiter", "limits")
AUDIT_NAMES = frozenset({"LangChainTracer", "CallbackHandler", "ConsoleCallbackHandler", "FileCallbackHandler"})
AUDIT_MODULES = ("langfuse", "opentelemetry", "phoenix", "arize", "mlflow", "helicone", "openinference")
GUARDRAIL_MODULES = ("nemoguardrails", "llm_guard", "guardrails", "presidio_analyzer", "presidio_anonymizer", "lakera")
GUARDRAIL_NAME_HINTS = ("guardrail", "moderation", "piimiddleware", "promptguard", "llmrails", "runnablerails")
STRUCTURED_OUTPUT_NAMES = frozenset(
    {"with_structured_output", "PydanticOutputParser", "JsonOutputParser", "PydanticToolsParser",
     "StructuredOutputParser", "JsonOutputToolsParser"}
)
SANDBOX_MODULES = ("e2b", "e2b_code_interpreter", "langchain_sandbox", "docker", "modal", "epicbox", "RestrictedPython")