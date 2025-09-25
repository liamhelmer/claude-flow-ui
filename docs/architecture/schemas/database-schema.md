# Database Schema Design

## PostgreSQL Schema Architecture

### Schema Organization
```sql
-- Main application schema
CREATE SCHEMA app;

-- Audit and logging schema
CREATE SCHEMA audit;

-- Configuration schema
CREATE SCHEMA config;
```

## Core Tables

### Users Table
```sql
CREATE TABLE app.users (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar_url TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    phone VARCHAR(20),
    date_of_birth DATE,
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    last_login_at TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_email ON app.users(email);
CREATE INDEX idx_users_username ON app.users(username);
CREATE INDEX idx_users_uuid ON app.users(uuid);
CREATE INDEX idx_users_status ON app.users(status);
CREATE INDEX idx_users_created_at ON app.users(created_at);
```

### Roles and Permissions
```sql
CREATE TABLE app.roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE app.permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE app.role_permissions (
    role_id INTEGER REFERENCES app.roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES app.permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE app.user_roles (
    user_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES app.roles(id) ON DELETE CASCADE,
    assigned_by INTEGER REFERENCES app.users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (user_id, role_id)
);
```

### Authentication & Sessions
```sql
CREATE TABLE app.user_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    ip_address INET,
    user_agent TEXT,
    device_info JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE app.refresh_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) REFERENCES app.user_sessions(session_id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE app.password_reset_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_user_sessions_user_id ON app.user_sessions(user_id);
CREATE INDEX idx_user_sessions_session_id ON app.user_sessions(session_id);
CREATE INDEX idx_user_sessions_expires_at ON app.user_sessions(expires_at);
CREATE INDEX idx_refresh_tokens_user_id ON app.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON app.refresh_tokens(expires_at);
```

### Example Resource Tables
```sql
-- Projects example
CREATE TABLE app.projects (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'archived', 'deleted')),
    visibility VARCHAR(20) DEFAULT 'private' CHECK (visibility IN ('public', 'private', 'internal')),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Project members
CREATE TABLE app.project_members (
    project_id INTEGER REFERENCES app.projects(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    permissions JSONB DEFAULT '{}',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);

-- Tasks example
CREATE TABLE app.tasks (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    project_id INTEGER REFERENCES app.projects(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    assignee_id INTEGER REFERENCES app.users(id),
    creator_id INTEGER REFERENCES app.users(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'todo',
    priority VARCHAR(20) DEFAULT 'medium',
    labels JSONB DEFAULT '[]',
    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for resources
CREATE INDEX idx_projects_owner_id ON app.projects(owner_id);
CREATE INDEX idx_projects_status ON app.projects(status);
CREATE INDEX idx_tasks_project_id ON app.tasks(project_id);
CREATE INDEX idx_tasks_assignee_id ON app.tasks(assignee_id);
CREATE INDEX idx_tasks_status ON app.tasks(status);
```

## Audit Schema

### Audit Log Table
```sql
CREATE TABLE audit.activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_activity_logs_user_id ON audit.activity_logs(user_id);
CREATE INDEX idx_activity_logs_action ON audit.activity_logs(action);
CREATE INDEX idx_activity_logs_resource ON audit.activity_logs(resource_type, resource_id);
CREATE INDEX idx_activity_logs_created_at ON audit.activity_logs(created_at);
```

## Configuration Schema

### System Configuration
```sql
CREATE TABLE config.system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE config.feature_flags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    description TEXT,
    rules JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Database Functions and Triggers

### Update Timestamps
```sql
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply to all tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON app.users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON app.projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON app.tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

### Audit Trigger
```sql
CREATE OR REPLACE FUNCTION audit_table_changes()
RETURNS TRIGGER AS $$
DECLARE
    old_data JSONB;
    new_data JSONB;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        old_data = to_jsonb(OLD);
        new_data = to_jsonb(NEW);

        INSERT INTO audit.activity_logs (
            action,
            resource_type,
            resource_id,
            old_values,
            new_values,
            created_at
        ) VALUES (
            'UPDATE',
            TG_TABLE_NAME,
            NEW.id::TEXT,
            old_data,
            new_data,
            NOW()
        );

        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        new_data = to_jsonb(NEW);

        INSERT INTO audit.activity_logs (
            action,
            resource_type,
            resource_id,
            new_values,
            created_at
        ) VALUES (
            'INSERT',
            TG_TABLE_NAME,
            NEW.id::TEXT,
            new_data,
            NOW()
        );

        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        old_data = to_jsonb(OLD);

        INSERT INTO audit.activity_logs (
            action,
            resource_type,
            resource_id,
            old_values,
            created_at
        ) VALUES (
            'DELETE',
            TG_TABLE_NAME,
            OLD.id::TEXT,
            old_data,
            NOW()
        );

        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
```

## Database Performance Optimization

### Connection Pooling Configuration
```javascript
// Database pool configuration
const poolConfig = {
    min: 5,                 // Minimum connections
    max: 25,                // Maximum connections
    acquireTimeoutMillis: 60000,
    createTimeoutMillis: 30000,
    destroyTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 200
};
```

### Query Optimization Guidelines

1. **Use appropriate indexes**
   - Primary keys and foreign keys
   - Frequently queried columns
   - Composite indexes for multi-column queries

2. **Avoid N+1 queries**
   - Use JOIN operations
   - Implement data loading strategies

3. **Pagination for large datasets**
   - Cursor-based pagination
   - Limit result sets

4. **Use database functions**
   - Aggregate operations in database
   - Complex calculations in PostgreSQL

## Backup and Recovery Strategy

### Backup Configuration
```bash
# Daily full backup
pg_dump -h localhost -U postgres -d app_db > backup_$(date +%Y%m%d).sql

# Point-in-time recovery setup
wal_level = replica
archive_mode = on
archive_command = 'cp %p /backup/archive/%f'
```

### Migration Strategy
```javascript
// Example migration structure
exports.up = function(knex) {
    return knex.schema.createTable('table_name', function(table) {
        table.increments('id').primary();
        table.timestamps(true, true);
    });
};

exports.down = function(knex) {
    return knex.schema.dropTable('table_name');
};
```

## Redis Integration Points

### Session Storage
```javascript
// Redis session configuration
const sessionConfig = {
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
};
```

### Caching Patterns
```javascript
// Cache-aside pattern
async function getUserById(id) {
    const cacheKey = `user:${id}`;

    // Try cache first
    const cached = await redis.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    // Fallback to database
    const user = await db.users.findById(id);
    if (user) {
        await redis.setex(cacheKey, 3600, JSON.stringify(user));
    }

    return user;
}
```

## Security Considerations

### Row-Level Security (RLS)
```sql
-- Enable RLS on users table
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY user_access_policy ON app.users
    FOR ALL TO app_user
    USING (id = current_setting('app.current_user_id')::integer);
```

### Data Encryption
```sql
-- Encrypt sensitive columns
ALTER TABLE app.users ADD COLUMN encrypted_ssn BYTEA;

-- Use pgcrypto for encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

This database schema provides a solid foundation for a production-ready REST API with proper normalization, indexing, auditing, and security considerations.