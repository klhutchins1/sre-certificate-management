"""
Application-wide constants for the Infrastructure Management System (IMS).

This module defines all constant values, mappings, and enumerations used throughout
IMS. It provides a single source of truth for:
- Platform types and their display representations
- Application types and categories
- Host classification types
- Environment definitions
- Certificate binding types
- Platform deployment types
- Domain classification TLDs
- Default rate limits and timeouts
- Certificate chain validation settings

Each constant is carefully chosen to maintain consistency across the application
and provide clear, meaningful values for the UI, API, and database operations.

Usage:
    Import this module wherever you need to reference a constant, e.g.:
        from infra_mgmt.constants import PLATFORM_F5, ENV_PRODUCTION

Maintainability:
    - Update this file when adding new platforms, environments, or types.
    - Keep all constant names UPPERCASE and group related constants together.
    - Document the rationale for any changes or additions.
"""

#------------------------------------------------------------------------------
# Platform Configuration
#------------------------------------------------------------------------------

# Platform display options with icons
# Maps internal platform identifiers to their user-friendly display names with icons
# Used in UI dropdowns and display components
platform_options = {
    'F5': "⚖️ F5 Load Balancer",
    'Akamai': "🌐 Akamai CDN",
    'Cloudflare': "☁️ Cloudflare",
    'IIS': "🪟 Windows Server (IIS)",
    'Connection': "🔌 Connection Certificate"
}

#------------------------------------------------------------------------------
# Application Types
#------------------------------------------------------------------------------

# Application types with icons
# Defines the different categories of applications that can use certificates
# Used for classification and filtering in the UI
app_types = {
    'Web': "🌐 Web Application",      # External-facing web applications
    'App': "🖥️ Internal Backend Application", # Internal backend applications
    'API': "🔌 API Service",          # REST/GraphQL/RPC services
    'Service': "⚙️ Background Service", # Internal processing services
    'Internal': "🔒 Internal Service"  # Internal-only applications
}

# List of valid application types for model validation
APP_TYPES = list(app_types.keys())

#------------------------------------------------------------------------------
# Host Classifications
#------------------------------------------------------------------------------

# Host type constants
# Defines the different types of hosts that can hold certificates
HOST_TYPE_SERVER = 'Server'           # Standard server instance
HOST_TYPE_LOAD_BALANCER = 'LoadBalancer'  # Load balancing endpoint
HOST_TYPE_CDN = 'CDN'                # Content Delivery Network node
HOST_TYPE_VIRTUAL = 'Virtual'         # Virtual host/server

# Complete list of valid host types for validation and UI dropdowns
HOST_TYPES = [
    HOST_TYPE_SERVER,
    HOST_TYPE_LOAD_BALANCER,
    HOST_TYPE_CDN,
    HOST_TYPE_VIRTUAL
]

#------------------------------------------------------------------------------
# Environment Definitions
#------------------------------------------------------------------------------

# Environment constants
# Defines the different deployment environments for certificates
ENV_PRODUCTION = 'Production'     # Live production environment
ENV_CERT = 'Cert'                # Certification/staging environment
ENV_DEVELOPMENT = 'Development'   # Development environment
ENV_INTERNAL = 'Internal'         # Internal network environment
ENV_EXTERNAL = 'External'         # External/public-facing environment

# Complete list of valid environments for validation and filtering
ENVIRONMENTS = [
    ENV_PRODUCTION,
    ENV_CERT,
    ENV_DEVELOPMENT,
    ENV_INTERNAL,
    ENV_EXTERNAL
]

#------------------------------------------------------------------------------
# Certificate Binding Types
#------------------------------------------------------------------------------

# Binding type constants
# Defines how certificates are bound to services/hosts
BINDING_TYPE_IP = 'IP'           # Bound to specific IP addresses
BINDING_TYPE_JWT = 'JWT'         # Used for JWT signing
BINDING_TYPE_CLIENT = 'Client'   # Used for client authentication

# Complete list of valid binding types for validation
BINDING_TYPES = [
    BINDING_TYPE_IP,
    BINDING_TYPE_JWT,
    BINDING_TYPE_CLIENT
]

#------------------------------------------------------------------------------
# Platform Types
#------------------------------------------------------------------------------

# Platform type constants
# Defines the supported platform types for certificate deployment
PLATFORM_F5 = 'F5'               # F5 Load Balancer platform
PLATFORM_AKAMAI = 'Akamai'       # Akamai CDN platform
PLATFORM_CLOUDFLARE = 'Cloudflare'  # Cloudflare services
PLATFORM_IIS = 'IIS'             # Windows IIS web server
PLATFORM_CONNECTION = 'Connection'  # Connection certificates

# Complete list of valid platforms for validation and filtering
PLATFORMS = [
    PLATFORM_F5,
    PLATFORM_AKAMAI,
    PLATFORM_CLOUDFLARE,
    PLATFORM_IIS,
    PLATFORM_CONNECTION
]

#------------------------------------------------------------------------------
# Domain Classification TLDs
#------------------------------------------------------------------------------

# Common internal TLDs and subdomains
# Used for automatic domain classification when not explicitly configured
INTERNAL_TLDS = {
    '.local', '.lan', '.internal', '.intranet', '.corp', '.private',
    '.test', '.example', '.invalid', '.localhost'
}

# Common external TLDs
# Used for automatic domain classification when not explicitly configured
EXTERNAL_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.info', '.biz', '.name', '.pro', '.museum', '.coop', '.aero',
    '.asia', '.cat', '.jobs', '.mobi', '.tel', '.travel'
}

#------------------------------------------------------------------------------
# Default Rate Limits and Timeouts
#------------------------------------------------------------------------------

# Default rate limits (requests per minute)
DEFAULT_RATE_LIMIT = 30  # Default 30 requests/minute (1/2sec)
INTERNAL_RATE_LIMIT = 60  # Default 60 requests/minute (1/sec)
EXTERNAL_RATE_LIMIT = 20  # Default 20 requests/minute (1/3sec)

# Default timeouts (seconds)
DNS_TIMEOUT = 5.0
SOCKET_TIMEOUT = 5.0
REQUEST_TIMEOUT = 5.0

#------------------------------------------------------------------------------
# Certificate Chain Validation Settings
#------------------------------------------------------------------------------

# Certificate chain validation settings
CHAIN_VALIDATION_TIMEOUT = 5.0
MAX_CHAIN_LENGTH = 10 