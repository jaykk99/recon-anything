"""Exchange-web detectors, block 6: GraphQL on exchange APIs.

Ten detectors over GraphQL schema/response/config text an
exchange site itself publishes: introspection results, console
exposure, disabled depth/complexity limits, admin mutations in
published schema text. Fixture/response analysis only - no query
is ever sent (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web6"

SPECS = [
    S("exch_graphql_introspection_result", "GraphQL Introspection Result Published in Assets",
      "medium",
      "Published assets contain a GraphQL introspection result (__schema payload), handing attackers the full API map - every type, field and mutation - without sending a single query.",
      "Disable introspection in production and strip introspection payloads from shipped assets and docs bundles.",
      patterns=[r"\"__schema\"\s*:\s*\{\s*\"(?:queryType|mutationType|types)\"",
                r"__schema\s*[:=]\s*\{[\s\S]{0,300}?mutationType"],
      category="api"),
    S("exch_graphql_console_ref", "GraphQL Console/Playground Referenced in Shipped Code",
      "medium",
      "Shipped code references a GraphQL console/playground endpoint (GraphiQL, Apollo sandbox, graphql-playground), which in production usually means the interactive console is reachable.",
      "Disable GraphQL consoles in production builds and remove their endpoint references from shipped code.",
      patterns=[r"['\"]/(?:graphiql|graphql-playground|graphql/console|playground/graphql)[^'\"]*['\"]",
                r"(?:graphiql|graphqlPlayground)\s*[:=]\s*['\"]https?://[^'\"]+['\"]"],
      category="api"),
    S("exch_graphql_depth_limit_disabled", "GraphQL Depth Limit Disabled in Config",
      "medium",
      "GraphQL config disables the query depth limit (depthLimit/maxDepth 0 or null), leaving deeply nested queries - a classic cheap denial-of-service and data-walk vector - unbounded.",
      "Set a finite query depth limit sized to the deepest legitimate client query.",
      patterns=[r"(?:depthLimit|maxDepth|depth_limit)\s*[:=]\s*(?:0|null|none|Infinity)\b",
                r"graphql[\s\S]{0,200}?(?:depthLimit|maxDepth)\s*[:=]\s*(?:0|null)"],
      category="api"),
    S("exch_graphql_persisted_query_map", "Persisted Query Map Published in Bundle",
      "low",
      "The bundle publishes the persisted-query map (operation names to hashes/documents), revealing the internal operation catalogue, including operations the UI never shows.",
      "Keep persisted-query maps server-side; the client needs only the hashes of the operations it actually sends.",
      patterns=[r"(?:persistedQueries|persistedQueryMap|operationMap)\s*[:=]\s*\{[^}]{0,400}?['\"][a-f0-9]{64}['\"]",
                r"['\"]sha256Hash['\"]\s*:\s*['\"][a-f0-9]{64}['\"][\s\S]{0,200}?(?:query|mutation)"],
      category="api"),
    S("exch_graphql_admin_mutation_schema", "Admin Mutations Present in Published GraphQL Schema Text",
      "high",
      "Published schema text in the bundle lists admin/treasury mutations, proving those operations exist on the reachable schema and naming them exactly for an attacker.",
      "Serve admin mutations on a separate internal schema/endpoint and publish only the customer schema.",
      patterns=[r"(?:mutation|type\s+Mutation)\s*\{[^}]{0,600}?(?:adminWithdraw|treasuryTransfer|admin[A-Z]\w*|internalTransfer)\s*\(",
                r"['\"](?:adminWithdraw|treasuryMove|forceWithdraw|adminAdjustBalance)['\"]\s*:\s*\{"],
      category="api"),
    S("exch_graphql_admin_endpoint_config", "Admin GraphQL Endpoint in Frontend Config",
      "medium",
      "Frontend config names an admin/internal GraphQL endpoint, disclosing the privileged schema's location to every visitor.",
      "Remove admin GraphQL endpoints from customer builds and network-restrict the admin schema.",
      patterns=[r"(?:graphql|gql)[A-Za-z_]*\s*[:=]\s*['\"]https?://[^'\"]*(?:admin|internal)[^'\"]*['\"]",
                r"['\"]/(?:admin|internal)/graphql['\"]"],
      category="api"),
    S("exch_graphql_debug_enabled", "GraphQL Debug/Playground Enabled in Production Config",
      "medium",
      "GraphQL server config in shipped code enables debug mode or the playground in a production profile, which typically also turns on verbose errors and introspection.",
      "Ship production GraphQL config with debug and playground off, and gate verbose errors behind internal flags.",
      patterns=[r"(?:graphql|apollo|ApolloServer)[\s\S]{0,300}?(?:debug|playground|introspection)\s*[:=]\s*true",
                r"(?:debug|playground)\s*[:=]\s*true[\s\S]{0,300}?(?:graphql|apollo)"],
      category="api"),
    S("exch_graphql_complexity_limit_disabled", "GraphQL Complexity Limit Disabled in Config",
      "medium",
      "GraphQL config disables query complexity limits, so a single expensive query (wide lists, nested connections) can be repeated at no cost to the caller.",
      "Enable complexity analysis with a budget sized to legitimate client queries.",
      patterns=[r"(?:complexityLimit|maxComplexity|queryComplexity)\s*[:=]\s*(?:0|null|none|Infinity)\b",
                r"graphql[\s\S]{0,200}?(?:complexityLimit|maxComplexity)\s*[:=]\s*(?:0|null)"],
      category="api"),
    S("exch_graphql_subscription_token_url", "GraphQL Subscription Auth Token in Connection URL",
      "medium",
      "GraphQL subscription setup puts the auth token in the socket connection URL/params shipped in code, leaking it to logs and history like any URL token.",
      "Pass subscription auth in connectionParams over the socket handshake or a header, never in a URL.",
      patterns=[r"(?:subscriptions|graphql-ws|SubscriptionClient)[\s\S]{0,300}?wss?://[^'\"\s]+[?&](?:token|auth)=",
                r"connectionParams[\s\S]{0,200}?['\"]wss?://[^'\"]*\?token="],
      category="api"),
    S("exch_graphql_internal_schema_types", "Internal GraphQL Types Embedded in Bundle Schema Text",
      "medium",
      "Schema text embedded in the bundle defines internal-only types (treasury/internal account types), exposing the internal data model even where the operations are not listed.",
      "Publish a customer-only schema; strip internal types from any schema text shipped to browsers.",
      patterns=[r"type\s+(?:Internal|Treasury|Admin)[A-Za-z]*\s*\{\s*(?:id|balance|amount|status)\s*[:=]",
                r"type\s+\w*(?:InternalAccount|TreasuryWallet|OpsLedger)\w*\s*\{"],
      category="api"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web6(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
