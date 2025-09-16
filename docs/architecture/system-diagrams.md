# System Architecture Diagrams

## Overview
This document contains architectural diagrams for the production-ready Node.js hello world application using C4 model notation.

## C4 Model Level 1: System Context

```mermaid
graph TB
    User[External User]
    Admin[System Administrator]
    Monitor[Monitoring System]

    System[Production Node.js App<br/>Hello World Service]

    User --> System
    Admin --> System
    System --> Monitor

    classDef system fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef external fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff

    class System system
    class User,Admin,Monitor external
```

## C4 Model Level 2: Container Diagram

```mermaid
graph TB
    subgraph "Production Node.js Application"
        WebApp[Web Application<br/>Node.js + Express]
        Config[Configuration<br/>Environment Variables]
        Logs[Logging System<br/>Winston + Files]
        Health[Health Checks<br/>HTTP Endpoints]
    end

    subgraph "External Systems"
        LB[Load Balancer<br/>NGINX/ALB]
        Monitoring[Monitoring<br/>Prometheus/Grafana]
        LogAggregator[Log Aggregation<br/>ELK/Fluentd]
    end

    User[External User] --> LB
    LB --> WebApp
    WebApp --> Config
    WebApp --> Logs
    WebApp --> Health
    Monitoring --> Health
    LogAggregator --> Logs

    classDef container fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef external fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff

    class WebApp,Config,Logs,Health container
    class User,LB,Monitoring,LogAggregator external
```

## C4 Model Level 3: Component Diagram

```mermaid
graph TB
    subgraph "Web Application Container"
        subgraph "Presentation Layer"
            Router[Express Router]
            Middleware[Middleware Stack]
            Controllers[Controllers]
            Validators[Input Validators]
        end

        subgraph "Business Layer"
            Services[Business Services]
            Models[Domain Models]
            Interfaces[Type Interfaces]
        end

        subgraph "Infrastructure Layer"
            Config[Configuration Manager]
            Logger[Logging Service]
            ErrorHandler[Error Handler]
            Security[Security Utils]
        end
    end

    Router --> Middleware
    Middleware --> Controllers
    Controllers --> Validators
    Controllers --> Services
    Services --> Models
    Services --> Logger
    Controllers --> ErrorHandler
    Middleware --> Security
    Services --> Config

    classDef presentation fill:#e377c2,stroke:#333,stroke-width:2px,color:#fff
    classDef business fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef infrastructure fill:#d62728,stroke:#333,stroke-width:2px,color:#fff

    class Router,Middleware,Controllers,Validators presentation
    class Services,Models,Interfaces business
    class Config,Logger,ErrorHandler,Security infrastructure
```

## Request Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant LB as Load Balancer
    participant MW as Middleware
    participant Ctrl as Controller
    participant Svc as Service
    participant Log as Logger

    Client->>LB: HTTP Request
    LB->>MW: Route Request
    MW->>MW: Security Check
    MW->>MW: Rate Limiting
    MW->>MW: Request Logging
    MW->>Ctrl: Process Request
    Ctrl->>Ctrl: Input Validation
    Ctrl->>Svc: Business Logic
    Svc->>Log: Log Operation
    Svc->>Ctrl: Return Result
    Ctrl->>MW: Response
    MW->>LB: HTTP Response
    LB->>Client: Final Response
```

## Error Handling Flow

```mermaid
graph TD
    Request[Incoming Request] --> Middleware[Middleware Pipeline]
    Middleware --> Error{Error Occurred?}
    Error -->|No| Controller[Controller Logic]
    Error -->|Yes| ErrorHandler[Global Error Handler]

    Controller --> BusinessLogic[Business Logic]
    BusinessLogic --> ServiceError{Service Error?}
    ServiceError -->|No| Success[Success Response]
    ServiceError -->|Yes| ErrorHandler

    ErrorHandler --> LogError[Log Error]
    ErrorHandler --> ErrorType{Error Type?}

    ErrorType -->|Validation| ValidationResponse[400 Bad Request]
    ErrorType -->|Authentication| AuthResponse[401 Unauthorized]
    ErrorType -->|Authorization| AuthzResponse[403 Forbidden]
    ErrorType -->|Not Found| NotFoundResponse[404 Not Found]
    ErrorType -->|Internal| InternalResponse[500 Internal Error]

    LogError --> Response[Error Response]
    Success --> Client[Client Response]
    ValidationResponse --> Client
    AuthResponse --> Client
    AuthzResponse --> Client
    NotFoundResponse --> Client
    InternalResponse --> Client

    classDef success fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef error fill:#d62728,stroke:#333,stroke-width:2px,color:#fff
    classDef process fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff

    class Success,Client success
    class ErrorHandler,LogError,ValidationResponse,AuthResponse,AuthzResponse,NotFoundResponse,InternalResponse error
    class Request,Middleware,Controller,BusinessLogic process
```

## Health Check Architecture

```mermaid
graph TD
    subgraph "Health Check Endpoints"
        Liveness[/health/live<br/>Liveness Probe]
        Readiness[/health/ready<br/>Readiness Probe]
        Comprehensive[/health<br/>Comprehensive Check]
    end

    subgraph "Health Checkers"
        AppHealth[Application Health]
        DBHealth[Database Health]
        CacheHealth[Cache Health]
        ExtHealth[External Service Health]
    end

    subgraph "Monitoring Systems"
        K8s[Kubernetes Probes]
        Prometheus[Prometheus Metrics]
        AlertManager[Alert Manager]
    end

    Liveness --> AppHealth
    Readiness --> DBHealth
    Readiness --> CacheHealth
    Comprehensive --> AppHealth
    Comprehensive --> DBHealth
    Comprehensive --> CacheHealth
    Comprehensive --> ExtHealth

    K8s --> Liveness
    K8s --> Readiness
    Prometheus --> Comprehensive
    AlertManager --> Prometheus

    classDef endpoint fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef checker fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef monitor fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff

    class Liveness,Readiness,Comprehensive endpoint
    class AppHealth,DBHealth,CacheHealth,ExtHealth checker
    class K8s,Prometheus,AlertManager monitor
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Load Balancer Layer"
        LB[NGINX/ALB<br/>Load Balancer]
    end

    subgraph "Kubernetes Cluster"
        subgraph "Namespace: production"
            subgraph "Pod 1"
                App1[Node.js App<br/>Instance 1]
            end
            subgraph "Pod 2"
                App2[Node.js App<br/>Instance 2]
            end
            subgraph "Pod 3"
                App3[Node.js App<br/>Instance 3]
            end
        end

        Service[Kubernetes Service]
        ConfigMap[ConfigMap<br/>Configuration]
        Secret[Secret<br/>Sensitive Data]
    end

    subgraph "Monitoring Stack"
        Prometheus[Prometheus<br/>Metrics Collection]
        Grafana[Grafana<br/>Visualization]
        AlertManager[AlertManager<br/>Alerting]
    end

    subgraph "Logging Stack"
        Fluentd[Fluentd<br/>Log Collection]
        Elasticsearch[Elasticsearch<br/>Log Storage]
        Kibana[Kibana<br/>Log Analysis]
    end

    Internet --> LB
    LB --> Service
    Service --> App1
    Service --> App2
    Service --> App3

    ConfigMap --> App1
    ConfigMap --> App2
    ConfigMap --> App3

    Secret --> App1
    Secret --> App2
    Secret --> App3

    App1 --> Prometheus
    App2 --> Prometheus
    App3 --> Prometheus

    App1 --> Fluentd
    App2 --> Fluentd
    App3 --> Fluentd

    Prometheus --> Grafana
    Prometheus --> AlertManager
    Fluentd --> Elasticsearch
    Elasticsearch --> Kibana

    classDef lb fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff
    classDef app fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef k8s fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef monitor fill:#d62728,stroke:#333,stroke-width:2px,color:#fff
    classDef log fill:#9467bd,stroke:#333,stroke-width:2px,color:#fff

    class LB lb
    class App1,App2,App3 app
    class Service,ConfigMap,Secret k8s
    class Prometheus,Grafana,AlertManager monitor
    class Fluentd,Elasticsearch,Kibana log
```

## Security Architecture

```mermaid
graph TD
    Internet[Internet Traffic]

    subgraph "Security Layers"
        WAF[Web Application Firewall]
        RateLimit[Rate Limiting]
        CORS[CORS Protection]
        Headers[Security Headers]
        Auth[Authentication]
        Authz[Authorization]
        Validation[Input Validation]
        Sanitization[Output Sanitization]
    end

    subgraph "Application"
        App[Node.js Application]
    end

    Internet --> WAF
    WAF --> RateLimit
    RateLimit --> CORS
    CORS --> Headers
    Headers --> Auth
    Auth --> Authz
    Authz --> Validation
    Validation --> Sanitization
    Sanitization --> App

    classDef security fill:#d62728,stroke:#333,stroke-width:2px,color:#fff
    classDef app fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef external fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff

    class WAF,RateLimit,CORS,Headers,Auth,Authz,Validation,Sanitization security
    class App app
    class Internet external
```

## Data Flow Architecture

```mermaid
graph LR
    subgraph "Client Layer"
        Browser[Web Browser]
        Mobile[Mobile App]
        API[API Client]
    end

    subgraph "Gateway Layer"
        LB[Load Balancer]
        Gateway[API Gateway]
    end

    subgraph "Application Layer"
        Auth[Auth Service]
        Business[Business Logic]
        Cache[Cache Layer]
    end

    subgraph "Data Layer"
        Database[(Database)]
        Files[(File Storage)]
        Logs[(Log Storage)]
    end

    Browser --> LB
    Mobile --> LB
    API --> Gateway

    LB --> Auth
    Gateway --> Auth

    Auth --> Business
    Business --> Cache
    Business --> Database
    Business --> Files
    Business --> Logs

    classDef client fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef gateway fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff
    classDef app fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef data fill:#d62728,stroke:#333,stroke-width:2px,color:#fff

    class Browser,Mobile,API client
    class LB,Gateway gateway
    class Auth,Business,Cache app
    class Database,Files,Logs data
```

## Performance Monitoring Architecture

```mermaid
graph TB
    subgraph "Application Metrics"
        AppMetrics[Application Metrics<br/>Response Time, Throughput]
        BusinessMetrics[Business Metrics<br/>Feature Usage, Errors]
        TechMetrics[Technical Metrics<br/>CPU, Memory, Disk]
    end

    subgraph "Collection Layer"
        Prometheus[Prometheus<br/>Metrics Collection]
        Jaeger[Jaeger<br/>Distributed Tracing]
        Logs[Centralized Logging<br/>ELK Stack]
    end

    subgraph "Analysis Layer"
        Grafana[Grafana<br/>Visualization]
        Kibana[Kibana<br/>Log Analysis]
        AlertManager[AlertManager<br/>Alerting]
    end

    subgraph "Response Layer"
        PagerDuty[PagerDuty<br/>Incident Management]
        Slack[Slack<br/>Notifications]
        AutoScale[Auto Scaling<br/>Resource Management]
    end

    AppMetrics --> Prometheus
    BusinessMetrics --> Prometheus
    TechMetrics --> Prometheus

    AppMetrics --> Jaeger
    AppMetrics --> Logs

    Prometheus --> Grafana
    Prometheus --> AlertManager
    Logs --> Kibana

    AlertManager --> PagerDuty
    AlertManager --> Slack
    AlertManager --> AutoScale

    classDef metrics fill:#1f77b4,stroke:#333,stroke-width:2px,color:#fff
    classDef collection fill:#2ca02c,stroke:#333,stroke-width:2px,color:#fff
    classDef analysis fill:#ff7f0e,stroke:#333,stroke-width:2px,color:#fff
    classDef response fill:#d62728,stroke:#333,stroke-width:2px,color:#fff

    class AppMetrics,BusinessMetrics,TechMetrics metrics
    class Prometheus,Jaeger,Logs collection
    class Grafana,Kibana,AlertManager analysis
    class PagerDuty,Slack,AutoScale response
```

## Notes
- All diagrams use standard C4 model notation
- Security considerations are integrated throughout the architecture
- Performance and monitoring are built-in from the start
- The architecture supports both horizontal and vertical scaling
- Health checks are designed for Kubernetes deployment patterns