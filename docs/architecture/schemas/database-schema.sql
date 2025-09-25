-- Production-Ready REST API Database Schema
-- PostgreSQL 14+ with Multi-Tenant Architecture

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create dedicated schemas for system and tenant data
CREATE SCHEMA IF NOT EXISTS system_data;
CREATE SCHEMA IF NOT EXISTS audit_data;

-- Set default schema
SET search_path TO system_data, public;

-- =====================================================
-- SYSTEM-LEVEL TABLES (Shared across all tenants)
-- =====================================================

-- Tenants table (system-wide)
CREATE TABLE system_data.tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    settings JSONB DEFAULT '{}',
    subscription_tier VARCHAR(50) DEFAULT 'basic',
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- Tenant schemas management
CREATE TABLE system_data.tenant_schemas (
    tenant_id UUID REFERENCES system_data.tenants(id) ON DELETE CASCADE,
    schema_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (tenant_id, schema_name)
);

-- System users (platform administrators)
CREATE TABLE system_data.system_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'admin',
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API Keys for system access
CREATE TABLE system_data.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES system_data.tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    permissions JSONB DEFAULT '[]',
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting tracking
CREATE TABLE system_data.rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(255) NOT NULL, -- IP, user_id, or api_key
    endpoint VARCHAR(255),
    requests_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_duration_seconds INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(identifier, endpoint, window_start)
);

-- =====================================================
-- TENANT-SPECIFIC SCHEMA TEMPLATE
-- =====================================================

-- Function to create tenant schema
CREATE OR REPLACE FUNCTION create_tenant_schema(tenant_uuid UUID, schema_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Create schema
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);

    -- Set search path to new schema
    EXECUTE format('SET search_path TO %I, public', schema_name);

    -- Users table (tenant-specific)
    EXECUTE format('
        CREATE TABLE %I.users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID DEFAULT %L,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255),
            first_name VARCHAR(100),
            last_name VARCHAR(100),
            phone VARCHAR(20),
            avatar_url VARCHAR(500),
            timezone VARCHAR(50) DEFAULT ''UTC'',
            locale VARCHAR(10) DEFAULT ''en'',
            is_active BOOLEAN DEFAULT true,
            email_verified_at TIMESTAMP WITH TIME ZONE,
            last_login_at TIMESTAMP WITH TIME ZONE,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            deleted_at TIMESTAMP WITH TIME ZONE
        )', schema_name, tenant_uuid);

    -- Roles table
    EXECUTE format('
        CREATE TABLE %I.roles (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(100) NOT NULL,
            description TEXT,
            permissions JSONB DEFAULT ''[]'',
            is_system_role BOOLEAN DEFAULT false,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(name)
        )', schema_name);

    -- User roles junction table
    EXECUTE format('
        CREATE TABLE %I.user_roles (
            user_id UUID REFERENCES %I.users(id) ON DELETE CASCADE,
            role_id UUID REFERENCES %I.roles(id) ON DELETE CASCADE,
            granted_by UUID REFERENCES %I.users(id),
            granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE,
            PRIMARY KEY (user_id, role_id)
        )', schema_name, schema_name, schema_name, schema_name);

    -- Sessions table
    EXECUTE format('
        CREATE TABLE %I.user_sessions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES %I.users(id) ON DELETE CASCADE,
            refresh_token_hash VARCHAR(255) NOT NULL,
            device_info JSONB DEFAULT ''{}'',
            ip_address INET,
            user_agent TEXT,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )', schema_name, schema_name);

    -- Password reset tokens
    EXECUTE format('
        CREATE TABLE %I.password_reset_tokens (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES %I.users(id) ON DELETE CASCADE,
            token_hash VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            used_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )', schema_name, schema_name);

    -- Organizations within tenant (sub-tenancy)
    EXECUTE format('
        CREATE TABLE %I.organizations (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(255) NOT NULL,
            description TEXT,
            settings JSONB DEFAULT ''{}'',
            owner_id UUID REFERENCES %I.users(id),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            deleted_at TIMESTAMP WITH TIME ZONE
        )', schema_name, schema_name);

    -- User organization membership
    EXECUTE format('
        CREATE TABLE %I.organization_members (
            organization_id UUID REFERENCES %I.organizations(id) ON DELETE CASCADE,
            user_id UUID REFERENCES %I.users(id) ON DELETE CASCADE,
            role VARCHAR(50) DEFAULT ''member'',
            joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            PRIMARY KEY (organization_id, user_id)
        )', schema_name, schema_name, schema_name);

    -- Generic resources table (extensible for different resource types)
    EXECUTE format('
        CREATE TABLE %I.resources (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            type VARCHAR(100) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            data JSONB DEFAULT ''{}'',
            owner_id UUID REFERENCES %I.users(id),
            organization_id UUID REFERENCES %I.organizations(id),
            status VARCHAR(50) DEFAULT ''active'',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            deleted_at TIMESTAMP WITH TIME ZONE
        )', schema_name, schema_name, schema_name);

    -- Resource permissions
    EXECUTE format('
        CREATE TABLE %I.resource_permissions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            resource_id UUID REFERENCES %I.resources(id) ON DELETE CASCADE,
            user_id UUID REFERENCES %I.users(id) ON DELETE CASCADE,
            permission VARCHAR(50) NOT NULL, -- read, write, admin, etc.
            granted_by UUID REFERENCES %I.users(id),
            granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE,
            UNIQUE(resource_id, user_id, permission)
        )', schema_name, schema_name, schema_name, schema_name);

    -- Activity logs
    EXECUTE format('
        CREATE TABLE %I.activity_logs (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES %I.users(id) ON DELETE SET NULL,
            resource_type VARCHAR(100),
            resource_id UUID,
            action VARCHAR(100) NOT NULL,
            details JSONB DEFAULT ''{}'',
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )', schema_name, schema_name);

    -- Create indexes for performance
    EXECUTE format('CREATE INDEX idx_%I_users_email ON %I.users(email)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_users_tenant_active ON %I.users(tenant_id, is_active)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_users_created_at ON %I.users(created_at)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_user_sessions_user_id ON %I.user_sessions(user_id)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_user_sessions_expires_at ON %I.user_sessions(expires_at)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_resources_owner_type ON %I.resources(owner_id, type)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_resources_org_type ON %I.resources(organization_id, type)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_activity_logs_user_created ON %I.activity_logs(user_id, created_at)', schema_name, schema_name);
    EXECUTE format('CREATE INDEX idx_%I_activity_logs_resource ON %I.activity_logs(resource_type, resource_id)', schema_name, schema_name);

    -- Insert default roles
    EXECUTE format('
        INSERT INTO %I.roles (name, description, permissions, is_system_role) VALUES
        (''admin'', ''Full administrative access'', ''["*:*"]'', true),
        (''user'', ''Standard user access'', ''["resource:read", "resource:create", "profile:update"]'', true),
        (''viewer'', ''Read-only access'', ''["resource:read", "profile:view"]'', true)
    ', schema_name);

    -- Record schema creation in system table
    INSERT INTO system_data.tenant_schemas (tenant_id, schema_name) VALUES (tenant_uuid, schema_name);

    -- Reset search path
    SET search_path TO system_data, public;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- AUDIT TABLES (Cross-tenant audit trail)
-- =====================================================

CREATE TABLE audit_data.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES system_data.tenants(id),
    user_id UUID,
    table_name VARCHAR(100),
    operation VARCHAR(10) CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    old_values JSONB,
    new_values JSONB,
    changed_fields TEXT[],
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Partition audit_log by month for better performance
CREATE TABLE audit_data.audit_log_y2025m01 PARTITION OF audit_data.audit_log
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Create indexes on system tables
CREATE INDEX idx_tenants_slug ON system_data.tenants(slug);
CREATE INDEX idx_tenants_status ON system_data.tenants(status);
CREATE INDEX idx_tenants_created_at ON system_data.tenants(created_at);
CREATE INDEX idx_api_keys_tenant_active ON system_data.api_keys(tenant_id, is_active);
CREATE INDEX idx_api_keys_hash ON system_data.api_keys(key_hash);
CREATE INDEX idx_rate_limits_identifier_window ON system_data.rate_limits(identifier, window_start);
CREATE INDEX idx_audit_log_tenant_created ON audit_data.audit_log(tenant_id, created_at);
CREATE INDEX idx_audit_log_user_created ON audit_data.audit_log(user_id, created_at);

-- =====================================================
-- TRIGGERS AND FUNCTIONS
-- =====================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to system tables
CREATE TRIGGER trigger_tenants_updated_at
    BEFORE UPDATE ON system_data.tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_system_users_updated_at
    BEFORE UPDATE ON system_data.system_users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to create audit trail
CREATE OR REPLACE FUNCTION create_audit_trail()
RETURNS TRIGGER AS $$
DECLARE
    tenant_uuid UUID;
BEGIN
    -- Extract tenant_id if available
    IF TG_OP = 'DELETE' THEN
        tenant_uuid := OLD.tenant_id;
    ELSE
        tenant_uuid := NEW.tenant_id;
    END IF;

    INSERT INTO audit_data.audit_log (
        tenant_id,
        user_id,
        table_name,
        operation,
        old_values,
        new_values,
        changed_fields
    ) VALUES (
        tenant_uuid,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END,
        TG_TABLE_NAME,
        TG_OP,
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN row_to_json(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN row_to_json(NEW) ELSE NULL END,
        CASE WHEN TG_OP = 'UPDATE' THEN
            ARRAY(SELECT key FROM jsonb_each(to_jsonb(NEW)) WHERE to_jsonb(NEW) ->> key != to_jsonb(OLD) ->> key)
        ELSE NULL END
    );

    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- ROW LEVEL SECURITY (RLS) SETUP
-- =====================================================

-- Enable RLS on tenant table
ALTER TABLE system_data.tenants ENABLE ROW LEVEL SECURITY;

-- Create RLS policies (example - adjust based on your authentication system)
CREATE POLICY tenant_isolation ON system_data.tenants
    USING (id = current_setting('app.current_tenant_id', true)::UUID);

-- =====================================================
-- CLEANUP AND MAINTENANCE
-- =====================================================

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    schema_rec RECORD;
BEGIN
    FOR schema_rec IN
        SELECT schema_name FROM system_data.tenant_schemas
    LOOP
        EXECUTE format('
            DELETE FROM %I.user_sessions
            WHERE expires_at < NOW()
        ', schema_rec.schema_name);

        GET DIAGNOSTICS deleted_count = deleted_count + ROW_COUNT;
    END LOOP;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old rate limit records
CREATE OR REPLACE FUNCTION cleanup_rate_limits()
RETURNS INTEGER AS $$
BEGIN
    DELETE FROM system_data.rate_limits
    WHERE window_start < NOW() - INTERVAL '1 day';

    RETURN ROW_COUNT;
END;
$$ LANGUAGE plpgsql;

-- Example: Create a tenant schema
-- SELECT create_tenant_schema('123e4567-e89b-12d3-a456-426614174000', 'tenant_acme');

-- Reset search path
SET search_path TO public;

-- Grant necessary permissions (adjust based on your application user)
-- GRANT USAGE ON SCHEMA system_data TO app_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA system_data TO app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA system_data TO app_user;