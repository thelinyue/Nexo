-- Nexo v0.1.12 单一初始 Baseline。
--
-- 该文件直接创建 0001-0019 及 mesh_identities.online 补丁收敛后的最终结构。
-- 历史迁移文件仅保留用于发布审计；运行时不再逐个执行历史迁移。
-- 现有数据库必须已经记录 schema_migrations=19，不能通过此文件补齐旧版本。
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', '默认租户');

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('system_admin', 'tenant')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    active_site_gateway_device_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT REFERENCES sites(id),
    name TEXT NOT NULL,
    os TEXT,
    architecture TEXT,
    agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'offline',
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    enrolled_at TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS site_networks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT NOT NULL REFERENCES sites(id),
    name TEXT NOT NULL,
    publisher_device_id TEXT NOT NULL REFERENCES devices(id),
    interface_id TEXT,
    address_family TEXT NOT NULL CHECK (address_family IN ('ipv4', 'ipv6')),
    source TEXT NOT NULL DEFAULT 'direct_interface'
        CHECK (source IN ('direct_interface', 'manual')),
    current_prefix TEXT,
    last_prefix TEXT,
    follow_prefix_changes INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    deletion_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subnet_access (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_network_id TEXT NOT NULL REFERENCES site_networks(id),
    scope TEXT NOT NULL DEFAULT 'tenant_mesh' CHECK (scope = 'tenant_mesh'),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, site_network_id)
);

CREATE TABLE IF NOT EXISTS site_links (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    left_site_id TEXT NOT NULL REFERENCES sites(id),
    right_site_id TEXT NOT NULL REFERENCES sites(id),
    left_ipv4_next_hop TEXT,
    left_ipv6_next_hop TEXT,
    right_ipv4_next_hop TEXT,
    right_ipv6_next_hop TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    deletion_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (left_site_id < right_site_id),
    UNIQUE (tenant_id, left_site_id, right_site_id)
);

CREATE TABLE IF NOT EXISTS site_link_networks (
    site_link_id TEXT NOT NULL REFERENCES site_links(id) ON DELETE CASCADE,
    site_network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    side TEXT NOT NULL CHECK (side IN ('left', 'right')),
    PRIMARY KEY (site_link_id, site_network_id)
);

CREATE TABLE IF NOT EXISTS public_domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0,
    https_enabled INTEGER NOT NULL DEFAULT 1,
    certificate_mode TEXT NOT NULL DEFAULT 'cloudflare'
        CHECK (certificate_mode IN ('manual', 'cloudflare')),
    acme_environment TEXT NOT NULL DEFAULT 'production'
        CHECK (acme_environment IN ('staging', 'production')),
    secret_dir TEXT NOT NULL,
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'checking', 'configuring', 'ready', 'retrying', 'rate_limited', 'error')),
    apply_error TEXT,
    error_code TEXT,
    dns_check_json TEXT NOT NULL DEFAULT '{}',
    root_certificate_status TEXT NOT NULL DEFAULT 'pending',
    root_certificate_not_before INTEGER,
    root_certificate_not_after INTEGER,
    root_certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    wildcard_certificate_status TEXT NOT NULL DEFAULT 'pending',
    wildcard_certificate_not_before INTEGER,
    wildcard_certificate_not_after INTEGER,
    wildcard_certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    retry_after INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER,
    dns_management_enabled INTEGER NOT NULL DEFAULT 0,
    dns_target_ipv4 TEXT,
    dns_target_ipv6 TEXT,
    dns_management_status TEXT NOT NULL DEFAULT 'disabled'
        CHECK (dns_management_status IN ('disabled', 'pending', 'previewed', 'applying', 'ready', 'drifted', 'conflict', 'error')),
    dns_management_error TEXT,
    dns_management_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, domain)
);

-- 这是 0010 的单例投影，保留在 v0.1.12 Baseline 中以确保 Baseline
-- 与 0001-0019 的最终结构一致；0020 OIDC 迁移会原子删除它。
CREATE TABLE IF NOT EXISTS public_entry_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    base_domain TEXT,
    https_enabled INTEGER NOT NULL DEFAULT 0,
    certificate_mode TEXT NOT NULL DEFAULT 'none'
        CHECK (certificate_mode IN ('none', 'manual', 'cloudflare')),
    acme_environment TEXT NOT NULL DEFAULT 'production'
        CHECK (acme_environment IN ('staging', 'production')),
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'not_configured'
        CHECK (apply_status IN ('not_configured', 'configuring', 'ready', 'error')),
    apply_error TEXT,
    certificate_not_before INTEGER,
    certificate_not_after INTEGER,
    certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    dns_check_json TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO public_entry_settings (id, tenant_id)
VALUES (1, 'default');

CREATE TABLE IF NOT EXISTS tunnels (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'http', 'https')),
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    public_port INTEGER,
    hostname TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_error TEXT,
    apply_revision INTEGER NOT NULL DEFAULT 0,
    origin_protocol TEXT,
    origin_tls_server_name TEXT,
    origin_tls_verification TEXT NOT NULL DEFAULT 'system',
    service_name TEXT,
    bridge_socket_path TEXT,
    origin_ca_secret_path TEXT,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    deleted_at INTEGER,
    deletion_requested INTEGER NOT NULL DEFAULT 0,
    deletion_revision INTEGER,
    public_domain_id TEXT REFERENCES public_domains(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT REFERENCES tenants(id),
    actor_user_id TEXT REFERENCES users(id),
    event_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pending_enrollments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT REFERENCES sites(id),
    token_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'awaiting_approval', 'approved', 'consumed', 'expired', 'revoked')
    ),
    expires_at INTEGER NOT NULL,
    device_id TEXT REFERENCES devices(id),
    requested_name TEXT,
    requested_os TEXT,
    requested_architecture TEXT,
    requested_agent_version TEXT,
    requested_capabilities_json TEXT NOT NULL DEFAULT '[]',
    requested_csr_pem TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TEXT,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS device_identities (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    certificate_pem TEXT,
    certificate_fingerprint TEXT,
    issued_at TEXT,
    expires_at INTEGER,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS server_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ca_certificate_pem TEXT NOT NULL,
    ca_private_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_control_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_capability_reports (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    report_json TEXT NOT NULL,
    reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gateway_network_states (
    site_network_id TEXT PRIMARY KEY REFERENCES site_networks(id) ON DELETE CASCADE,
    desired_prefix TEXT NOT NULL,
    applied_prefix TEXT,
    desired_revision INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking'
        CHECK (apply_status IN ('disabled', 'checking', 'applying', 'ready', 'retrying', 'failed')),
    apply_error TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mesh_tenant_mappings (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_user_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'ready', 'failed')),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mesh_identities (
    nexo_device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_node_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'ready'
        CHECK (state IN ('enrolling', 'ready', 'mesh_identity_mismatch', 'disabled', 'failed')),
    tailscale_ipv4 TEXT,
    tailscale_ipv6 TEXT,
    hostname TEXT,
    online INTEGER NOT NULL DEFAULT 0,
    last_verified_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mesh_enrollment_attempts (
    id TEXT PRIMARY KEY,
    nexo_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_pre_auth_key_id TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'consumed', 'expired', 'revoked', 'failed')),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gateway_route_applies (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    site_link_id TEXT NOT NULL DEFAULT '',
    desired_revision INTEGER NOT NULL DEFAULT 1,
    local_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (local_status IN ('pending', 'applied', 'failed', 'disabled', 'upgrade_required')),
    control_plane_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (control_plane_status IN ('pending', 'discovered', 'approved', 'serving', 'failed', 'disabled')),
    remote_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (remote_status IN ('pending', 'accepted', 'failed', 'disabled')),
    applied_prefix TEXT,
    last_error TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, network_id, site_link_id)
);

CREATE TABLE IF NOT EXISTS site_link_route_confirmations (
    site_link_id TEXT NOT NULL REFERENCES site_links(id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    confirmed_at TEXT NOT NULL,
    PRIMARY KEY (site_link_id, site_id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_digest TEXT NOT NULL UNIQUE,
    csrf_digest TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('local_http', 'public_https')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    source TEXT NOT NULL,
    attempted_at INTEGER NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_recovery_sessions (
    id TEXT PRIMARY KEY,
    code_digest TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS tunnel_applied_states (
    tunnel_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,
    applied_revision INTEGER NOT NULL,
    applied_config_json TEXT NOT NULL,
    apply_status TEXT NOT NULL DEFAULT 'checking'
        CHECK (apply_status IN ('disabled', 'checking', 'applying', 'ready', 'retrying', 'failed')),
    apply_error TEXT,
    last_checked_at INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS public_domain_migrations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_domain_id TEXT NOT NULL REFERENCES public_domains(id),
    to_domain_id TEXT NOT NULL REFERENCES public_domains(id),
    status TEXT NOT NULL DEFAULT 'preparing'
        CHECK (status IN ('preparing', 'switching', 'waiting_devices', 'completed', 'failed')),
    desired_revision INTEGER NOT NULL DEFAULT 0,
    total_devices INTEGER NOT NULL DEFAULT 0,
    acknowledged_devices INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS public_domain_migration_devices (
    migration_id TEXT NOT NULL REFERENCES public_domain_migrations(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sent', 'acknowledged', 'failed', 'upgrade_required')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    acknowledged_at INTEGER,
    PRIMARY KEY (migration_id, device_id)
);

CREATE TABLE IF NOT EXISTS tailscale_device_metadata (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    registration_method TEXT NOT NULL DEFAULT 'browser'
        CHECK (registration_method IN ('browser', 'auth_key', 'oidc')),
    tags_json TEXT NOT NULL DEFAULT '[]',
    tailscale_ipv4 TEXT,
    tailscale_ipv6 TEXT,
    expires_at INTEGER,
    control_plane_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (control_plane_state IN ('pending', 'ready', 'isolated', 'revoked', 'unknown')),
    external_node INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS tailscale_external_nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT NOT NULL,
    node_json TEXT NOT NULL,
    discovered_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    claimed_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    claim_state TEXT NOT NULL DEFAULT 'isolated'
        CHECK (claim_state IN ('isolated', 'claimed', 'rejected'))
);

CREATE TABLE IF NOT EXISTS tailscale_auth_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    headscale_key_id TEXT NOT NULL UNIQUE,
    key_digest TEXT NOT NULL,
    label TEXT NOT NULL,
    reusable INTEGER NOT NULL DEFAULT 0,
    ephemeral INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'used', 'expired', 'revoked', 'unknown')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    revealed_at INTEGER
);

CREATE TABLE IF NOT EXISTS mesh_access_rules (
    id TEXT PRIMARY KEY,
    owner_tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL
        CHECK (target_type IN ('device', 'network', 'exit_node', 'file_share')),
    target_id TEXT NOT NULL,
    protocols_json TEXT NOT NULL DEFAULT '["tcp", "udp"]',
    ports_json TEXT NOT NULL DEFAULT '["*"]',
    ssh_enabled INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    desired_revision INTEGER NOT NULL DEFAULT 1,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'checking', 'applying', 'ready', 'error', 'disabled')),
    apply_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (owner_tenant_id, name)
);

CREATE TABLE IF NOT EXISTS mesh_access_grants (
    rule_id TEXT NOT NULL REFERENCES mesh_access_rules(id) ON DELETE CASCADE,
    grantee_tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'accepted'
        CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    accepted_at INTEGER,
    PRIMARY KEY (rule_id, grantee_tenant_id)
);

CREATE TABLE IF NOT EXISTS public_domain_dns_records (
    id TEXT PRIMARY KEY,
    public_domain_id TEXT NOT NULL REFERENCES public_domains(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA')),
    record_name TEXT NOT NULL CHECK (record_name IN ('@', '*')),
    cloudflare_record_id TEXT,
    last_applied_content TEXT NOT NULL,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'ready', 'drifted', 'error')),
    apply_error TEXT,
    created_by_nexo INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (public_domain_id, record_type, record_name)
);

CREATE TABLE IF NOT EXISTS public_domain_certificate_progress (
    public_domain_id TEXT NOT NULL REFERENCES public_domains(id) ON DELETE CASCADE,
    certificate_type TEXT NOT NULL CHECK (certificate_type IN ('root', 'wildcard')),
    stage TEXT NOT NULL DEFAULT 'waiting_configuration'
        CHECK (stage IN ('waiting_configuration', 'presenting_dns', 'waiting_dns', 'validating', 'issued', 'active', 'retry_wait', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_event_at INTEGER,
    next_retry_at INTEGER,
    error_code TEXT,
    error_message TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (public_domain_id, certificate_type)
);

CREATE TABLE IF NOT EXISTS public_domain_runtime_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_domain_id TEXT REFERENCES public_domains(id) ON DELETE CASCADE,
    domain TEXT,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    stage TEXT,
    summary TEXT NOT NULL,
    error_code TEXT,
    retry_at INTEGER,
    technical_detail TEXT,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_site_networks_site ON site_networks(site_id);
CREATE INDEX IF NOT EXISTS idx_site_networks_publisher ON site_networks(publisher_device_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_public_port ON tunnels(public_port);
CREATE INDEX IF NOT EXISTS idx_tunnels_hostname ON tunnels(hostname);
CREATE INDEX IF NOT EXISTS idx_tunnels_public_domain ON tunnels(public_domain_id);
CREATE INDEX IF NOT EXISTS idx_pending_enrollments_tenant ON pending_enrollments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pending_enrollments_status ON pending_enrollments(status);
CREATE INDEX IF NOT EXISTS idx_mesh_identities_tenant ON mesh_identities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mesh_enrollment_attempts_device
    ON mesh_enrollment_attempts(nexo_device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_digest ON auth_sessions(session_digest);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_window
    ON auth_login_attempts(username, source, attempted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_public_domains_primary
    ON public_domains(tenant_id) WHERE is_primary = 1;
CREATE INDEX IF NOT EXISTS idx_public_domains_tenant
    ON public_domains(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tailscale_device_metadata_user
    ON tailscale_device_metadata(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tailscale_external_nodes_state
    ON tailscale_external_nodes(claim_state, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_tailscale_auth_keys_tenant
    ON tailscale_auth_keys(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mesh_access_rules_owner
    ON mesh_access_rules(owner_tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_mesh_access_grants_tenant
    ON mesh_access_grants(grantee_tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_public_domain_dns_records_domain
    ON public_domain_dns_records(public_domain_id);
CREATE INDEX IF NOT EXISTS idx_public_domain_certificate_progress_stage
    ON public_domain_certificate_progress(stage, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_public_domain_runtime_events_tenant_time
    ON public_domain_runtime_events(tenant_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_public_domain_runtime_events_domain_time
    ON public_domain_runtime_events(public_domain_id, occurred_at DESC, id DESC);

INSERT INTO schema_migrations (version) VALUES (19);
