# System Architecture Diagrams

## Overview

This document contains comprehensive architectural diagrams for the REST API system, including C4 model diagrams, component interactions, and data flow visualizations.

## C4 Model Architecture

### Level 1: System Context Diagram

```mermaid
graph TB
    subgraph "External Systems"
        USER[Web Users]
        MOBILE[Mobile Users]
        API_CLIENT[API Clients]
        ADMIN[System Administrators]
    end

    subgraph "REST API System"
        API[REST API System<br/>Node.js/Express]
    end

    subgraph "External Services"
        EMAIL[Email Service<br/>SMTP/SendGrid]
        SMS[SMS Service<br/>Twilio]
        PAYMENT[Payment Gateway<br/>Stripe]
        STORAGE[File Storage<br/>AWS S3]
        MONITORING[Monitoring<br/>DataDog/New Relic]
    end

    USER --> API
    MOBILE --> API
    API_CLIENT --> API
    ADMIN --> API

    API --> EMAIL
    API --> SMS
    API --> PAYMENT
    API --> STORAGE
    API --> MONITORING

    style API fill:#e1f5fe
    style EMAIL fill:#f3e5f5
    style SMS fill:#f3e5f5
    style PAYMENT fill:#f3e5f5
    style STORAGE fill:#f3e5f5
    style MONITORING fill:#f3e5f5
```

### Level 2: Container Diagram

```mermaid
graph TB
    subgraph "Users"
        WEB[Web Browser]
        MOBILE_APP[Mobile App]
        API_CLIENT[Third-party APIs]
    end

    subgraph "REST API System"
        LB[Load Balancer<br/>nginx/HAProxy]

        subgraph "API Gateway Layer"
            GATEWAY[API Gateway<br/>Kong/Envoy]
        end

        subgraph "Application Layer"
            APP1[API Instance 1<br/>Node.js/Express]
            APP2[API Instance 2<br/>Node.js/Express]
            APP3[API Instance N<br/>Node.js/Express]
        end

        subgraph "Data Layer"
            REDIS[Redis Cluster<br/>Caching & Sessions]
            POSTGRES[PostgreSQL<br/>Primary Database]
            POSTGRES_RO[PostgreSQL<br/>Read Replicas]
        end

        subgraph "Monitoring & Logging"
            PROMETHEUS[Prometheus<br/>Metrics Collection]
            GRAFANA[Grafana<br/>Visualization]
            ELK[ELK Stack<br/>Log Aggregation]
            JAEGER[Jaeger<br/>Distributed Tracing]
        end
    end

    subgraph "External Services"
        EMAIL_SVC[Email Services]
        CLOUD_STORAGE[Cloud Storage]
        PAYMENT_SVC[Payment Services]
    end

    WEB --> LB
    MOBILE_APP --> LB
    API_CLIENT --> LB

    LB --> GATEWAY
    GATEWAY --> APP1
    GATEWAY --> APP2
    GATEWAY --> APP3

    APP1 --> REDIS
    APP2 --> REDIS
    APP3 --> REDIS

    APP1 --> POSTGRES
    APP2 --> POSTGRES
    APP3 --> POSTGRES

    APP1 --> POSTGRES_RO
    APP2 --> POSTGRES_RO
    APP3 --> POSTGRES_RO

    APP1 --> PROMETHEUS
    APP2 --> PROMETHEUS
    APP3 --> PROMETHEUS

    PROMETHEUS --> GRAFANA
    APP1 --> ELK
    APP2 --> ELK
    APP3 --> ELK

    APP1 --> JAEGER
    APP2 --> JAEGER
    APP3 --> JAEGER

    APP1 --> EMAIL_SVC
    APP1 --> CLOUD_STORAGE
    APP1 --> PAYMENT_SVC

    style LB fill:#ffecb3
    style GATEWAY fill:#e8f5e8
    style APP1 fill:#e1f5fe
    style APP2 fill:#e1f5fe
    style APP3 fill:#e1f5fe
    style REDIS fill:#ffebee
    style POSTGRES fill:#e8f5e8
    style POSTGRES_RO fill:#e8f5e8
```

### Level 3: Component Diagram (Application Layer)

```mermaid
graph TB
    subgraph "API Gateway"
        RATE_LIMITER[Rate Limiter]
        AUTH_GATEWAY[Authentication]
        ROUTING[Request Routing]
    end

    subgraph "Express Application"
        subgraph "Middleware Stack"
            SECURITY[Security Headers]
            LOGGING[Request Logging]
            CORS[CORS Handler]
            BODY_PARSER[Body Parser]
            VALIDATION[Input Validation]
            AUTH_MW[Authentication MW]
            AUTHZ_MW[Authorization MW]
            CACHING_MW[Caching MW]
        end

        subgraph "Controllers"
            AUTH_CTRL[Auth Controller]
            USER_CTRL[User Controller]
            PROJECT_CTRL[Project Controller]
            ADMIN_CTRL[Admin Controller]
            HEALTH_CTRL[Health Controller]
        end

        subgraph "Services"
            AUTH_SVC[Auth Service]
            USER_SVC[User Service]
            PROJECT_SVC[Project Service]
            EMAIL_SVC[Email Service]
            CACHE_SVC[Cache Service]
            NOTIFICATION_SVC[Notification Service]
        end

        subgraph "Repositories"
            USER_REPO[User Repository]
            PROJECT_REPO[Project Repository]
            AUDIT_REPO[Audit Repository]
            BASE_REPO[Base Repository]
        end

        subgraph "Models & Schemas"
            USER_MODEL[User Model]
            PROJECT_MODEL[Project Model]
            VALIDATION_SCHEMA[Validation Schemas]
            API_TYPES[API Types]
        end

        subgraph "Utilities"
            JWT_UTIL[JWT Utils]
            CRYPTO_UTIL[Crypto Utils]
            LOGGER_UTIL[Logger Utils]
            METRICS_UTIL[Metrics Utils]
        end

        ERROR_HANDLER[Global Error Handler]
    end

    subgraph "External Integrations"
        DB_POOL[Database Pool]
        REDIS_CLIENT[Redis Client]
        SMTP_CLIENT[SMTP Client]
        STORAGE_CLIENT[Storage Client]
    end

    ROUTING --> SECURITY
    SECURITY --> LOGGING
    LOGGING --> CORS
    CORS --> BODY_PARSER
    BODY_PARSER --> VALIDATION
    VALIDATION --> AUTH_MW
    AUTH_MW --> AUTHZ_MW
    AUTHZ_MW --> CACHING_MW

    CACHING_MW --> AUTH_CTRL
    CACHING_MW --> USER_CTRL
    CACHING_MW --> PROJECT_CTRL
    CACHING_MW --> ADMIN_CTRL
    CACHING_MW --> HEALTH_CTRL

    AUTH_CTRL --> AUTH_SVC
    USER_CTRL --> USER_SVC
    PROJECT_CTRL --> PROJECT_SVC
    ADMIN_CTRL --> USER_SVC
    ADMIN_CTRL --> PROJECT_SVC

    AUTH_SVC --> USER_REPO
    USER_SVC --> USER_REPO
    PROJECT_SVC --> PROJECT_REPO
    PROJECT_SVC --> USER_REPO

    USER_REPO --> BASE_REPO
    PROJECT_REPO --> BASE_REPO
    AUDIT_REPO --> BASE_REPO

    BASE_REPO --> DB_POOL
    CACHE_SVC --> REDIS_CLIENT
    EMAIL_SVC --> SMTP_CLIENT

    AUTH_SVC --> JWT_UTIL
    AUTH_SVC --> CRYPTO_UTIL
    USER_SVC --> CACHE_SVC
    PROJECT_SVC --> NOTIFICATION_SVC

    ERROR_HANDLER --> LOGGER_UTIL

    style SECURITY fill:#ffcdd2
    style AUTH_MW fill:#c8e6c9
    style AUTHZ_MW fill:#c8e6c9
    style CACHING_MW fill:#fff3e0
```

## Data Flow Diagrams

### User Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant Gateway as API Gateway
    participant Auth as Auth Controller
    participant AuthSvc as Auth Service
    participant Redis
    participant DB as PostgreSQL
    participant JWT as JWT Service

    Client->>Gateway: POST /auth/login
    Gateway->>Auth: Forward request
    Auth->>AuthSvc: authenticate(credentials)
    AuthSvc->>DB: findUserByEmail(email)
    DB-->>AuthSvc: user data
    AuthSvc->>AuthSvc: verifyPassword(hash)
    AuthSvc->>JWT: generateTokenPair(user)
    JWT-->>AuthSvc: {accessToken, refreshToken}
    AuthSvc->>Redis: storeSession(sessionData)
    Redis-->>AuthSvc: session stored
    AuthSvc-->>Auth: authentication result
    Auth-->>Gateway: HTTP 200 + tokens
    Gateway-->>Client: authentication response

    Note over Client,JWT: Token includes user ID, roles, permissions, tenant ID
```

### API Request Processing Flow

```mermaid
sequenceDiagram
    participant Client
    participant LB as Load Balancer
    participant Gateway as API Gateway
    participant MW as Middleware Stack
    participant Controller
    participant Service
    participant Repository
    participant DB as Database
    participant Cache as Redis

    Client->>LB: HTTP Request
    LB->>Gateway: Route to instance
    Gateway->>MW: Security checks
    MW->>MW: Rate limiting
    MW->>MW: Authentication
    MW->>MW: Authorization
    MW->>Cache: Check cache

    alt Cache Hit
        Cache-->>MW: Cached response
        MW-->>Gateway: Return cached data
    else Cache Miss
        MW->>Controller: Process request
        Controller->>Service: Business logic
        Service->>Repository: Data access
        Repository->>DB: SQL query
        DB-->>Repository: Query result
        Repository-->>Service: Domain objects
        Service-->>Controller: Processed data
        Controller->>Cache: Store in cache
        Controller-->>MW: Response data
    end

    MW-->>Gateway: HTTP Response
    Gateway-->>LB: Response
    LB-->>Client: Final response
```

### Multi-Tenant Data Isolation Flow

```mermaid
graph TB
    subgraph "Request Processing"
        REQUEST[Incoming Request]
        AUTH[Authentication]
        TENANT_EXTRACT[Extract Tenant Context]
    end

    subgraph "Database Layer"
        TENANT_MIDDLEWARE[Tenant Isolation MW]
        QUERY_BUILDER[Query Builder]
        RLS[Row Level Security]
    end

    subgraph "PostgreSQL Database"
        subgraph "Tenant A Schema"
            USERS_A[users]
            PROJECTS_A[projects]
            AUDIT_A[audit_log]
        end

        subgraph "Tenant B Schema"
            USERS_B[users]
            PROJECTS_B[projects]
            AUDIT_B[audit_log]
        end

        subgraph "Shared Schema"
            TENANTS[tenants]
            SYSTEM_CONFIG[system_config]
        end
    end

    REQUEST --> AUTH
    AUTH --> TENANT_EXTRACT
    TENANT_EXTRACT --> TENANT_MIDDLEWARE
    TENANT_MIDDLEWARE --> QUERY_BUILDER
    QUERY_BUILDER --> RLS

    RLS --> USERS_A
    RLS --> PROJECTS_A
    RLS --> AUDIT_A

    RLS --> USERS_B
    RLS --> PROJECTS_B
    RLS --> AUDIT_B

    RLS --> TENANTS
    RLS --> SYSTEM_CONFIG

    style TENANT_MIDDLEWARE fill:#e8f5e8
    style RLS fill:#ffecb3
    style USERS_A fill:#e3f2fd
    style USERS_B fill:#fce4ec
```

### Caching Strategy Diagram

```mermaid
graph TB
    subgraph "Caching Layers"
        CDN[CDN Cache<br/>CloudFlare/AWS CF]
        API_GATEWAY_CACHE[API Gateway Cache<br/>Kong/Envoy]

        subgraph "Application Cache"
            APP_CACHE[Application Cache<br/>Node.js Memory]
            REDIS_CACHE[Redis Cache<br/>Distributed]
        end

        DATABASE[PostgreSQL<br/>Query Cache]
    end

    subgraph "Cache Types"
        STATIC[Static Assets<br/>24h TTL]
        API_RESPONSE[API Responses<br/>5-15m TTL]
        USER_SESSION[User Sessions<br/>24h TTL]
        DB_QUERY[DB Query Results<br/>1-60m TTL]
    end

    subgraph "Cache Invalidation"
        TTL[Time-based TTL]
        EVENT_DRIVEN[Event-driven<br/>Pub/Sub]
        TAG_BASED[Tag-based<br/>Dependencies]
        MANUAL[Manual<br/>Admin Tools]
    end

    CDN --> STATIC
    API_GATEWAY_CACHE --> API_RESPONSE
    REDIS_CACHE --> USER_SESSION
    REDIS_CACHE --> DB_QUERY
    APP_CACHE --> DB_QUERY

    TTL --> CDN
    TTL --> API_GATEWAY_CACHE
    EVENT_DRIVEN --> REDIS_CACHE
    TAG_BASED --> APP_CACHE
    MANUAL --> REDIS_CACHE

    style CDN fill:#e8f5e8
    style REDIS_CACHE fill:#ffebee
    style DATABASE fill:#e1f5fe
```

## Security Architecture Diagram

```mermaid
graph TB
    subgraph "Security Layers"
        subgraph "Network Security"
            WAF[Web Application Firewall]
            DDoS[DDoS Protection]
            FIREWALL[Network Firewall]
        end

        subgraph "Application Security"
            RATE_LIMIT[Rate Limiting]
            INPUT_VAL[Input Validation]
            OUTPUT_ENC[Output Encoding]
            SQL_INJECT[SQL Injection Prevention]
            XSS_PROTECT[XSS Protection]
        end

        subgraph "Authentication & Authorization"
            JWT_AUTH[JWT Authentication]
            MFA[Multi-Factor Auth]
            RBAC[Role-Based Access Control]
            TENANT_ISO[Tenant Isolation]
        end

        subgraph "Data Security"
            ENCRYPT_REST[Encryption at Rest]
            ENCRYPT_TRANSIT[Encryption in Transit]
            PASSWORD_HASH[Password Hashing]
            DATA_MASK[Data Masking]
        end

        subgraph "Monitoring & Audit"
            SECURITY_LOG[Security Logging]
            INTRUSION_DETECT[Intrusion Detection]
            AUDIT_TRAIL[Audit Trail]
            ANOMALY_DETECT[Anomaly Detection]
        end
    end

    subgraph "Threat Model"
        OWASP_TOP10[OWASP Top 10]
        DATA_BREACH[Data Breach]
        ACCOUNT_TAKEOVER[Account Takeover]
        PRIVILEGE_ESC[Privilege Escalation]
        API_ABUSE[API Abuse]
    end

    WAF --> OWASP_TOP10
    RATE_LIMIT --> API_ABUSE
    JWT_AUTH --> ACCOUNT_TAKEOVER
    RBAC --> PRIVILEGE_ESC
    ENCRYPT_REST --> DATA_BREACH
    AUDIT_TRAIL --> PRIVILEGE_ESC

    style WAF fill:#ffcdd2
    style JWT_AUTH fill:#c8e6c9
    style ENCRYPT_REST fill:#fff3e0
    style SECURITY_LOG fill:#e1f5fe
```

## Deployment Architecture

### Production Environment

```mermaid
graph TB
    subgraph "Internet"
        USERS[Users]
    end

    subgraph "Edge/CDN"
        CDN[CloudFlare CDN]
    end

    subgraph "AWS/GCP/Azure Cloud"
        subgraph "Load Balancer Tier"
            ALB[Application Load Balancer]
        end

        subgraph "Application Tier"
            subgraph "Availability Zone A"
                APP_A1[API Instance A1]
                APP_A2[API Instance A2]
            end

            subgraph "Availability Zone B"
                APP_B1[API Instance B1]
                APP_B2[API Instance B2]
            end
        end

        subgraph "Data Tier"
            subgraph "Database Cluster"
                DB_MASTER[PostgreSQL Master]
                DB_REPLICA1[Read Replica 1]
                DB_REPLICA2[Read Replica 2]
            end

            subgraph "Cache Cluster"
                REDIS_M1[Redis Master 1]
                REDIS_M2[Redis Master 2]
                REDIS_M3[Redis Master 3]
                REDIS_S1[Redis Slave 1]
                REDIS_S2[Redis Slave 2]
                REDIS_S3[Redis Slave 3]
            end
        end

        subgraph "Monitoring & Logging"
            PROMETHEUS[Prometheus]
            GRAFANA[Grafana]
            ELASTICSEARCH[Elasticsearch]
            KIBANA[Kibana]
            JAEGER[Jaeger]
        end

        subgraph "External Services"
            S3[AWS S3]
            SES[AWS SES]
            SECRETS[Secrets Manager]
        end
    end

    USERS --> CDN
    CDN --> ALB

    ALB --> APP_A1
    ALB --> APP_A2
    ALB --> APP_B1
    ALB --> APP_B2

    APP_A1 --> DB_MASTER
    APP_A2 --> DB_MASTER
    APP_B1 --> DB_MASTER
    APP_B2 --> DB_MASTER

    APP_A1 --> DB_REPLICA1
    APP_A2 --> DB_REPLICA1
    APP_B1 --> DB_REPLICA2
    APP_B2 --> DB_REPLICA2

    APP_A1 --> REDIS_M1
    APP_A2 --> REDIS_M2
    APP_B1 --> REDIS_M3
    APP_B2 --> REDIS_M1

    REDIS_M1 --> REDIS_S1
    REDIS_M2 --> REDIS_S2
    REDIS_M3 --> REDIS_S3

    APP_A1 --> PROMETHEUS
    APP_A2 --> PROMETHEUS
    APP_B1 --> PROMETHEUS
    APP_B2 --> PROMETHEUS

    APP_A1 --> ELASTICSEARCH
    APP_A2 --> ELASTICSEARCH
    APP_B1 --> ELASTICSEARCH
    APP_B2 --> ELASTICSEARCH

    APP_A1 --> S3
    APP_A1 --> SES
    APP_A1 --> SECRETS

    style ALB fill:#ffecb3
    style APP_A1 fill:#e1f5fe
    style DB_MASTER fill:#e8f5e8
    style REDIS_M1 fill:#ffebee
```

### Container Orchestration (Kubernetes)

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        subgraph "Ingress"
            INGRESS[Ingress Controller<br/>nginx/Traefik]
        end

        subgraph "Application Namespace"
            subgraph "API Deployment"
                API_POD1[API Pod 1]
                API_POD2[API Pod 2]
                API_POD3[API Pod 3]
            end

            API_SERVICE[API Service<br/>ClusterIP]
            API_HPA[Horizontal Pod Autoscaler]
        end

        subgraph "Data Namespace"
            subgraph "PostgreSQL"
                PG_MASTER[PostgreSQL Master]
                PG_REPLICA[PostgreSQL Replica]
                PG_PVC[Persistent Volume]
            end

            subgraph "Redis"
                REDIS_MASTER[Redis Master]
                REDIS_SENTINEL[Redis Sentinel]
            end
        end

        subgraph "Monitoring Namespace"
            PROMETHEUS_K8S[Prometheus]
            GRAFANA_K8S[Grafana]
            JAEGER_K8S[Jaeger]
        end

        subgraph "System Namespace"
            CONFIG_MAP[ConfigMaps]
            SECRETS_K8S[Secrets]
            SERVICE_ACCOUNT[Service Accounts]
        end
    end

    INGRESS --> API_SERVICE
    API_SERVICE --> API_POD1
    API_SERVICE --> API_POD2
    API_SERVICE --> API_POD3

    API_HPA --> API_POD1
    API_HPA --> API_POD2
    API_HPA --> API_POD3

    API_POD1 --> PG_MASTER
    API_POD2 --> PG_MASTER
    API_POD3 --> PG_MASTER

    API_POD1 --> PG_REPLICA
    API_POD2 --> PG_REPLICA
    API_POD3 --> PG_REPLICA

    API_POD1 --> REDIS_MASTER
    API_POD2 --> REDIS_MASTER
    API_POD3 --> REDIS_MASTER

    PG_MASTER --> PG_PVC
    PG_REPLICA --> PG_PVC

    API_POD1 --> CONFIG_MAP
    API_POD1 --> SECRETS_K8S
    API_POD1 --> SERVICE_ACCOUNT

    style INGRESS fill:#ffecb3
    style API_POD1 fill:#e1f5fe
    style API_HPA fill:#e8f5e8
    style PG_MASTER fill:#c8e6c9
    style REDIS_MASTER fill:#ffebee
```

## Performance & Scalability Diagrams

### Auto-scaling Architecture

```mermaid
graph TB
    subgraph "Load Metrics"
        CPU[CPU Usage > 70%]
        MEMORY[Memory > 80%]
        REQUEST_RATE[Request Rate > 1000/s]
        RESPONSE_TIME[Avg Response > 2s]
    end

    subgraph "Auto-scaling Controllers"
        HPA[Horizontal Pod Autoscaler]
        VPA[Vertical Pod Autoscaler]
        CA[Cluster Autoscaler]
    end

    subgraph "Scaling Actions"
        SCALE_OUT[Scale Out Pods]
        SCALE_UP[Scale Up Resources]
        ADD_NODES[Add Cluster Nodes]
    end

    subgraph "Application Instances"
        POD1[Pod 1]
        POD2[Pod 2]
        POD3[Pod 3]
        PODN[Pod N...]
    end

    CPU --> HPA
    MEMORY --> VPA
    REQUEST_RATE --> HPA
    RESPONSE_TIME --> HPA

    HPA --> SCALE_OUT
    VPA --> SCALE_UP
    CA --> ADD_NODES

    SCALE_OUT --> POD3
    SCALE_OUT --> PODN
    SCALE_UP --> POD1
    SCALE_UP --> POD2

    style HPA fill:#e8f5e8
    style SCALE_OUT fill:#fff3e0
    style POD1 fill:#e1f5fe
```

### Database Scaling Strategy

```mermaid
graph LR
    subgraph "Read/Write Separation"
        APP[Application]
        WRITE_ROUTER[Write Router]
        read_router[Read Router]

        MASTER[(Master DB<br/>Writes Only)]
        REPLICA1[(Read Replica 1)]
        REPLICA2[(Read Replica 2)]
        REPLICA3[(Read Replica 3)]
    end

    subgraph "Partitioning Strategy"
        TENANT_A[(Tenant A<br/>Partition)]
        TENANT_B[(Tenant B<br/>Partition)]
        TENANT_C[(Tenant C<br/>Partition)]
    end

    APP --> WRITE_ROUTER
    APP --> read_router

    WRITE_ROUTER --> MASTER
    read_router --> REPLICA1
    read_router --> REPLICA2
    read_router --> REPLICA3

    MASTER -.-> REPLICA1
    MASTER -.-> REPLICA2
    MASTER -.-> REPLICA3

    MASTER --> TENANT_A
    MASTER --> TENANT_B
    MASTER --> TENANT_C

    style APP fill:#e1f5fe
    style MASTER fill:#c8e6c9
    style REPLICA1 fill:#fff3e0
```

This comprehensive set of diagrams provides visual documentation of the entire system architecture, from high-level context down to detailed component interactions, supporting both development and operational understanding of the REST API system.