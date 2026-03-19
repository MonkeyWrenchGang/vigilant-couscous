# Architecture And Event Sequence Diagrams

## System Fit Diagram

```mermaid
flowchart LR
  subgraph callers [JackHenryCallerApplications]
    banno[Banno_Service]
    silverlake[SilverLake_Service]
    symitar[Symitar_Service]
    profitstars[ProfitStars_Service]
  end

  subgraph edge [IngressAndAPI]
    apiGateway[API_Gateway]
    tokenApi[TokenizationAPI_GKE_PrivateCluster]
  end

  subgraph identity [IdentityAndPolicy]
    workloadIdentity[WorkloadIdentity_GCP]
    grantTable[DelegationGrantTable\ncaller_app x institution_id]
    authPolicy[AuthZ_Policy\ndomain+scope+purpose]
    institutionRegistry[InstitutionRegistry\ninst_id → key_refs]
  end

  subgraph crypto [CryptographicLayer]
    pemKey[CloudKMS_PEK\nAES256_Envelope\nper-institution]
    pfkKey[CloudKMS_PFK\nHMAC_SHA256_Fingerprint\nper-institution REQUIRED]
  end

  subgraph data [VaultAndDataPlane]
    redisCache[Redis_HotCache\nkeyed by institution_id]
    spannerVault[Spanner_TokenVault\npartitioned by institution_id]
    spannerConfig[Spanner_InstitutionRegistry\nconfig table, IAM-isolated]
  end

  subgraph observability [AuditAndObservability]
    pubsubAudit[PubSub_AuditEvents\ncaller_app + institution_id]
    bigqueryAudit[BigQuery_AuditStore\nqueryable by institution_id]
    monitoring[CloudMonitoring_Alerts\nper-institution + per-app]
    sensitiveDataDiscovery[SensitiveData_DiscoveryScanner\nSR-08_Annual]
  end

  banno -->|WorkloadIdentity token + institution_id| apiGateway
  silverlake -->|WorkloadIdentity token + institution_id| apiGateway
  symitar -->|WorkloadIdentity token + institution_id| apiGateway
  profitstars -->|WorkloadIdentity token + institution_id| apiGateway
  apiGateway --> tokenApi
  tokenApi --> workloadIdentity
  tokenApi --> grantTable
  tokenApi --> authPolicy
  tokenApi --> institutionRegistry
  tokenApi --> pfkKey
  tokenApi --> pemKey
  tokenApi --> redisCache
  tokenApi --> spannerVault
  tokenApi --> spannerConfig
  tokenApi --> pubsubAudit
  pubsubAudit --> bigqueryAudit
  tokenApi --> monitoring
  sensitiveDataDiscovery -.->|scans| bigqueryAudit
  sensitiveDataDiscovery -.->|scans| spannerVault
```

**Key architectural properties:**
- All caller applications (Banno, SilverLake, Symitar, ProfitStars) authenticate via Workload Identity. `institution_id` is always a request parameter — never derived from the caller identity alone.
- The **Delegation Grant Table** is the primary cross-institution access control: maps `(caller_app_identity, institution_id)` to permitted operations, domains, and purposes.
- The **Institution Registry** maps `institution_id` to its Cloud KMS key references (PFK key name, PEK key name). Stored in a dedicated Spanner config table with IAM roles isolated from vault data tables.
- Both PFK and PEK are **institution-scoped** — one per institution. PFK (HMAC fingerprinting) and PEK (envelope encryption) are provisioned together at institution onboarding.
- All Spanner data is partitioned by `institution_id` as the leading key. Redis cache keys include `institution_id`.
- Audit events include both `caller_application` (JH product) and `institution_id` (bank/credit union) as mandatory indexed fields.
- Sensitive data discovery scanner runs out-of-band against all CDE-adjacent storage (SR-08).
- All human access to any component in the identity, crypto, and data subgraphs requires MFA (SR-07).

---

## Tokenize Sequence

```mermaid
sequenceDiagram
  participant Client as JH_CallerApp (e.g. Banno)
  participant Gateway as API_Gateway
  participant API as TokenizationAPI
  participant WI as WorkloadIdentity
  participant Grant as DelegationGrantTable
  participant Policy as AuthZ_Policy
  participant Registry as InstitutionRegistry
  participant Redis as Redis_Cache
  participant PFK as CloudKMS_PFK (institution-scoped)
  participant PEK as CloudKMS_PEK
  participant Spanner as Spanner_Vault
  participant Audit as PubSub_Audit

  Client->>Gateway: POST /v1/tokenize {institution_id, domain?, scope_qualifiers, token_purpose, token_mode, sensitive_value, sensitive_data_type, idempotency_key}
  Gateway->>API: ForwardRequest
  API->>WI: ResolveCallerAppIdentity
  WI-->>API: CallerAppIdentity (e.g. banno-payments@jh.iam)
  API->>Grant: CheckDelegation {caller_app, institution_id}
  Grant-->>API: Authorized or 403
  API->>Policy: ValidateScope {caller_app, institution_id, domain, scope_qualifiers, purpose}
  Policy-->>API: AllowOrDeny
  API->>Registry: LookupInstitutionKeys {institution_id}
  Registry-->>API: PFK_key_name, PEK_key_name

  alt REUSABLE mode
    API->>PFK: HMAC_SHA256(sensitive_value, institution_pfk)
    PFK-->>API: value_fingerprint
    API->>Redis: LookupToken {institution_id, domain, scope_qualifiers_canonical, purpose, value_fingerprint}
    alt cache hit
      Redis-->>API: ActiveToken
      API->>Audit: PublishTokenizeEvent {caller_app, institution_id, reused=true, domain, scope_qualifiers}
      API-->>Gateway: 200 TokenResponse
      Gateway-->>Client: 200 TokenResponse
    else cache miss — check vault
      API->>Spanner: LookupReusableToken {institution_id, domain, scope_qualifiers_canonical, purpose, value_fingerprint, state=ACTIVE}
      alt vault hit
        Spanner-->>API: ActiveTokenRecord
        API->>Redis: WriteThrough
        API->>Audit: PublishTokenizeEvent {caller_app, institution_id, reused=true}
        API-->>Gateway: 200 TokenResponse
        Gateway-->>Client: 200 TokenResponse
      else vault miss — mint new token
        API->>PEK: Encrypt_AES256GCM(sensitive_value, institution_pek)
        PEK-->>API: CiphertextAndMetadata
        API->>Spanner: UpsertSensitiveDataRecord + CreateTokenRecord {institution_id, domain, scope_qualifiers_canonical, purpose, caller_app, sensitive_data_type}
        Spanner-->>API: TokenRecord
        API->>Redis: WriteThrough
        API->>Audit: PublishTokenizeEvent {caller_app, institution_id, reused=false}
        API-->>Gateway: 200 TokenResponse
        Gateway-->>Client: 200 TokenResponse
      end
    end
  else ONE_TIME mode
    API->>PFK: HMAC_SHA256(sensitive_value, institution_pfk)
    PFK-->>API: value_fingerprint
    API->>PEK: Encrypt_AES256GCM(sensitive_value, institution_pek)
    PEK-->>API: CiphertextAndMetadata
    API->>Spanner: UpsertSensitiveDataRecord + CreateTokenRecord {institution_id, ONE_TIME, sensitive_data_type}
    Spanner-->>API: TokenRecord
    API->>Audit: PublishTokenizeEvent {caller_app, institution_id, mode=ONE_TIME}
    API-->>Gateway: 200 TokenResponse
    Gateway-->>Client: 200 TokenResponse
  end
```

---

## Detokenize Sequence

```mermaid
sequenceDiagram
  participant Client as JH_CallerApp (e.g. SilverLake)
  participant Gateway as API_Gateway
  participant API as TokenizationAPI
  participant WI as WorkloadIdentity
  participant Grant as DelegationGrantTable
  participant Policy as AuthZ_Policy
  participant Redis as Redis_Cache
  participant PEK as CloudKMS_PEK (institution-scoped)
  participant Spanner as Spanner_Vault
  participant Audit as PubSub_Audit

  Client->>Gateway: POST /v1/detokenize {institution_id, domain?, scope_qualifiers, token_purpose, token, request_context{reason_code, operator_id}, format_options}
  Gateway->>API: ForwardRequest
  API->>WI: ResolveCallerAppIdentity
  WI-->>API: CallerAppIdentity
  API->>API: ValidateReasonCode (reject 400 if missing or invalid enum)
  API->>Grant: CheckDelegation {caller_app, institution_id}
  Grant-->>API: Authorized or 403
  API->>Policy: ValidateDetokenizePermission {caller_app, institution_id, domain, scope_qualifiers, purpose}
  Policy-->>API: AllowOrDeny
  API->>Policy: CheckFullValueScope (only if return_type=FULL)
  Policy-->>API: AllowOrDeny

  note over API: Fail closed on ANY policy error — no fallback path

  API->>Redis: LookupTokenToCard {institution_id, token}
  alt cache hit
    Redis-->>API: SensitiveDataReference + PEK_key_name
  else cache miss
    API->>Spanner: ReadTokenAndSensitiveData {institution_id, token, domain, scope_qualifiers}
    Spanner-->>API: VaultRecord
    API->>Redis: PopulateHotCache
  end

  API->>PEK: Decrypt_AES256GCM(ciphertext, institution_pek)
  PEK-->>API: PlaintextSensitiveValue

  alt return_type = MASKED (default)
    API->>API: MaskValue (type-aware: PAN→411111******1111, BANK_ACCOUNT→******6789)
    API->>Audit: PublishDetokenizeEvent {caller_app, institution_id, reason_code, operator_id=unverified, return_type=MASKED}
    API-->>Gateway: 200 {token, sensitive_value=masked, sensitive_data_type}
    Gateway-->>Client: 200 MaskedValueResponse
  else return_type = FULL (full-value scope confirmed)
    API->>Audit: PublishDetokenizeEvent {caller_app, institution_id, reason_code, operator_id=unverified, return_type=FULL}
    API-->>Gateway: 200 {token, sensitive_value=full, sensitive_data_type}
    Gateway-->>Client: 200 FullValueResponse
  end
```

---

## Revoke Sequence

```mermaid
sequenceDiagram
  participant Client as JH_CallerApp
  participant Gateway as API_Gateway
  participant API as TokenizationAPI
  participant WI as WorkloadIdentity
  participant Grant as DelegationGrantTable
  participant Policy as AuthZ_Policy
  participant Spanner as Spanner_Vault
  participant Redis as Redis_Cache
  participant Audit as PubSub_Audit

  Client->>Gateway: POST /v1/tokens/revoke {institution_id, domain?, token OR value_fingerprint+scope_qualifiers, reason}
  Gateway->>API: ForwardRequest
  API->>WI: ResolveCallerAppIdentity
  WI-->>API: CallerAppIdentity
  API->>Grant: CheckDelegation {caller_app, institution_id}
  Grant-->>API: Authorized or 403
  API->>Policy: ValidateRevokePermission {caller_app, institution_id, domain}
  Policy-->>API: AllowOrDeny

  alt revoke by token
    API->>Spanner: SetTokenState {institution_id, token → REVOKED}
    Spanner-->>API: UpdatedCount
    API->>Redis: EvictToken {institution_id, token}
  else revoke by fingerprint selector
    API->>Spanner: SetTokensRevoked {institution_id, domain, value_fingerprint, scope_qualifiers_filter, ACTIVE → REVOKED}
    Spanner-->>API: UpdatedCount
    API->>Redis: EvictMatchingTokens {institution_id}
  end

  API->>Audit: PublishRevokeEvent {caller_app, institution_id, selector_type, reason, revoked_count}
  API-->>Gateway: 200 {revoked_count, request_id}
  Gateway-->>Client: 200 RevokeResponse
```

---

## Failure And Control Notes

- **Delegation check is step 2, always**: Before any vault operation, the service validates the calling application's delegation grant for the supplied `institution_id`. A misconfigured or compromised JH application that passes the wrong `institution_id` is blocked here.
- **Institution-scoped PFK as defense-in-depth**: Even if delegation check were bypassed, a token issued under institution A's PFK cannot produce a valid fingerprint match in institution B's vault. Cross-institution token reuse structurally fails at lookup. This applies uniformly across all sensitive data types (PAN, bank account numbers, etc.).
- **Detokenize fails closed**: Any policy check failure, grant lookup error, or scope mismatch returns an error. No fallback to allow. `institution_id` mismatch returns `404 TOKEN_NOT_FOUND` — same as not found — to avoid disclosing cross-institution token existence.
- **Cache is institution-partitioned**: Redis cache keys include `institution_id`. A cache implementation bug cannot serve institution A's data to institution B.
- **Audit events are dual-keyed**: Every event carries both `caller_application` (which JH product) and `institution_id` (which bank/credit union). This supports per-institution compliance reporting and per-application anomaly detection independently.
- **Sensitive data discovery (SR-08)**: Runs out-of-band against Cloud Logging buckets, BigQuery audit tables, Spanner exports, and Redis snapshots. Scans for all supported sensitive data types (PANs, bank account numbers). Findings trigger incident procedures per OR-04.
- **Domain defaults to "default"**: When `domain` is omitted from a request, the service applies `"default"` as the domain value. This simplifies single-domain deployments while preserving multi-domain isolation for callers that need it.
- **scope_qualifiers absorbs companion data**: Fields such as card expiry dates, routing numbers, and other metadata associated with a sensitive value are carried in `scope_qualifiers` rather than as top-level fields. This keeps the core API shape stable across different `sensitive_data_type` values.
- **Institution onboarding is a prerequisite**: The Institution Registry must contain a valid entry for `institution_id` with PFK and PEK key references before any API call for that institution will succeed.
