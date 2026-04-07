# Policy Catalog

This catalog lists all available policies in the Gateway Controllers Policy Hub, organized by category. Each entry links to the latest version documentation and includes a short description.

---

## REST API Policies

General-purpose policies for REST API traffic management, security, and transformation.

- [Advanced Rate Limiting](./advanced-ratelimit/v1.0/docs/advanced-ratelimit.md) — Enforces configurable rate limits using multiple algorithms (GCRA, fixed window) with flexible key extraction strategies, support for dynamic cost extraction from responses, and an optional Redis backend for distributed deployments.

- [Analytics Header Filter](./analytics-header-filter/v1.0/docs/analytics-header-filter.md) — Controls which request and response headers are sent to analytics backends using allow or deny modes; operates transparently without modifying the actual request or response.

- [API Key Authentication](./api-key-auth/v1.0/docs/apikey-authentication.md) — Validates API keys from request headers or query parameters against gateway-managed key lists before allowing access to protected resources.

- [Basic Authentication](./basic-auth/v1.0/docs/basic-auth.md) — Implements HTTP Basic Authentication by validating username and password credentials using constant-time comparison, with optional unauthenticated pass-through mode.

- [Basic Rate Limiting](./basic-ratelimit/v1.0/docs/basic-ratelimit.md) — Provides simplified per-route request rate limiting with a fixed key strategy, sharing the same backend and algorithm configuration as the advanced rate limiting policy.

- [CORS](./cors/v1.0/docs/cors.md) — Handles Cross-Origin Resource Sharing by validating preflight requests and adding appropriate CORS headers, with support for wildcard, exact, and regex-based origin patterns.

- [Dynamic Endpoint](./dynamic-endpoint/v1.0/docs/dynamic-endpoint.md) — Routes requests to a named upstream definition at request time, enabling per-operation upstream selection without changing the primary API structure.

- [Host Rewrite](./host-rewrite/v1.0/docs/host-rewrite.md) — Rewrites the Host header on upstream requests to a configured value, useful when the upstream service expects a specific hostname different from the incoming request.

- [JSON/XML Mediator](./json-xml-mediator/v1.0/docs/json-xml-mediator.md) — Provides bidirectional payload transformation between JSON and XML formats for both request and response flows, with automatic Content-Type header management.

- [JWT Authentication](./jwt-auth/v1.0/docs/jwt-authentication.md) — Validates JWT access tokens using one or more JWKS providers, with configurable issuer, audience, scope, and claim validation, plus downstream header mapping.

- [Log Message](./log-message/v1.0/docs/log-message.md) — Logs request and response payloads and headers for observability and debugging, with configurable header filtering, authorization header masking, and SSE streaming support.

- [Remove Headers](./remove-headers/v1.0/docs/remove-headers.md) — Removes specified HTTP headers from requests before forwarding to upstream services and/or from responses before returning to clients.

- [Request Rewrite](./request-rewrite/v1.0/docs/request-rewrite.md) — Rewrites request paths, query parameters, and HTTP methods using prefix replacement, full path replacement, or regex substitution, with optional conditional matching.

- [Respond](./respond/v1.0/docs/respond.md) — Returns an immediate HTTP response from the gateway without forwarding to the upstream backend, useful for mocking, maintenance mode, and feature gating.

- [Set Headers](./set-headers/v1.0/docs/set-headers.md) — Sets (overwrites) HTTP headers on requests and/or responses with static values; existing headers with the same name are replaced.

- [Subscription Validation](./subscription-validation/v1.0/docs/subscription-validation.md) — Validates incoming requests against active subscriptions using a token from a configurable header or cookie, with optional plan-based rate limiting enforcement.

- [Token Based Rate Limiting](./token-based-ratelimit/v1.0/docs/token-based-ratelimit.md) — Enforces rate limits on LLM API usage based on actual token consumption (prompt, completion, and total tokens) extracted automatically from LLM provider responses.

---

## AI Gateway Guardrails

Policies for AI/LLM API governance, prompt management, content safety, and cost control.

- [AWS Bedrock Guardrail](./aws-bedrock-guardrail/v1.0/docs/aws-bedrock-guardrail.md) — Validates request or response content against AWS Bedrock Guardrails for content filtering, topic detection, word filtering, and PII detection with masking or redaction support.

- [Azure Content Safety](./azure-content-safety-content-moderation/v1.0/docs/azure-content-safety.md) — Validates content against Microsoft Azure Content Safety API, detecting and blocking harmful content across hate speech, sexual content, self-harm, and violence categories with configurable severity thresholds.

- [Content Length Guardrail](./content-length-guardrail/v1.0/docs/content-length.md) — Validates the byte length of request or response content against configurable minimum and maximum thresholds, with SSE streaming support.

- [JSON Schema Guardrail](./json-schema-guardrail/v1.0/docs/json-schema.md) — Validates request or response JSON content against a JSON Schema Draft 7 definition to ensure payloads conform to expected formats, types, and constraints.

- [LLM Cost](./llm-cost/v1.0/docs/llm-cost.md) — Calculates the monetary cost of an LLM API call at response time using a built-in pricing database, storing the result in shared context for use by downstream policies such as cost-based rate limiting.

- [LLM Cost Based Rate Limiting](./llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) — Enforces monetary spending budgets on LLM API routes by reading pre-calculated costs from the LLM Cost policy and blocking requests when the configured dollar budget is exhausted.

- [Model Round Robin](./model-round-robin/v1.0/docs/model-round-robin.md) — Distributes LLM requests evenly across multiple configured AI models in a cyclic pattern, with automatic model suspension on 5xx or 429 failures.

- [Model Weighted Round Robin](./model-weighted-round-robin/v1.0/docs/model-weighted-round-robin.md) — Distributes LLM requests across multiple AI models based on configurable weights, routing proportionally more traffic to higher-weighted models, with automatic suspension for failing models.

- [PII Masking (Regex)](./pii-masking-regex/v1.0/docs/pii-masking-regex.md) — Detects and masks or permanently redacts Personally Identifiable Information from request and response bodies using configurable regex patterns, with automatic PII restoration in responses and SSE streaming support.

- [Prompt Decorator](./prompt-decorator/v1.0/docs/prompt-decorator.md) — Dynamically prepends or appends text or chat messages to specific fields in JSON payloads before forwarding to AI services, enabling consistent prompt injection or system persona definition.

- [Prompt Template](./prompt-template/v1.0/docs/prompt-template.md) — Replaces `template://` URI patterns in JSON payloads with predefined templates and parameter substitution, enabling reusable and parameterized prompts for LLM APIs.

- [Regex Guardrail](./regex-guardrail/v1.0/docs/regex.md) — Validates request or response content against configurable regular expression patterns, with support for inverted (blocklist/allowlist) logic, JSONPath extraction, and cross-chunk SSE streaming validation.

- [Semantic Cache](./semantic-cache/v1.0/docs/semantic-caching.md) — Caches LLM responses using vector similarity search so that semantically equivalent queries are served from cache, reducing upstream calls and cost; supports multiple embedding providers and vector databases.

- [Semantic Prompt Guard](./semantic-prompt-guard/v1.0/docs/semantic-prompt-guard.md) — Validates prompts using semantic similarity against configurable allow and deny phrase lists backed by embedding models, blocking semantically similar prohibited content or enforcing allowlist-only topics.

- [Semantic Tool Filtering](./semantic-tool-filtering/v1.0/docs/semantic-tool-filtering.md) — Dynamically filters the tools array in LLM requests based on semantic relevance to the user query using embedding vectors, reducing token consumption by sending only the most relevant tools to the model.

- [Sentence Count Guardrail](./sentence-count-guardrail/v1.0/docs/sentence-count.md) — Validates the sentence count of request or response content against configurable minimum and maximum thresholds, with SSE streaming support.

- [URL Guardrail](./url-guardrail/v1.0/docs/url.md) — Validates URLs found in request or response content by checking their reachability via DNS resolution or HTTP HEAD requests, with smart boundary detection for SSE streaming responses.

- [Word Count Guardrail](./word-count-guardrail/v1.0/docs/word-count.md) — Validates the word count of request or response content against configurable minimum and maximum thresholds, with SSE streaming support.

---

## MCP Policies

Policies for securing and managing Model Context Protocol (MCP) server traffic.

- [MCP ACL List](./mcp-acl-list/v1.0/docs/mcp-acl-list.md) — Provides access control for MCP tools, resources, and prompts using allow/deny mode with exceptions, filtering list responses and enforcing access rules on capability request paths.

- [MCP Authentication](./mcp-auth/v1.0/docs/mcp-authentication.md) — Secures MCP server traffic by validating JWT access tokens using configured key managers, with resource-specific security configuration, exception lists, and protected resource metadata support per the MCP specification.

- [MCP Authorization](./mcp-authz/v1.0/docs/mcp-authorization.md) — Provides fine-grained authorization for MCP tools, resources, prompts, and JSON-RPC methods based on JWT claims and OAuth scopes, with support for exact name matching and wildcard rules.

- [MCP Rewrite](./mcp-rewrite/v1.0/docs/mcp-rewrite.md) — Exposes user-facing names for MCP tools, resources, and prompts while mapping them to different backend capability names, and filters list responses to only include configured capabilities.

- [Semantic Tool Filtering (MCP)](./semantic-tool-filtering/v1.0/docs/semantic-tool-filtering.md) — Dynamically filters MCP tool definitions based on semantic relevance to the user query using embedding vectors, reducing token consumption by sending only the most relevant tools to the LLM.
