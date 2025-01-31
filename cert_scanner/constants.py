# Platform display options with icons
platform_options = {
    'F5': "🔄 F5 Load Balancer",
    'Akamai': "🌐 Akamai CDN",
    'Cloudflare': "☁️ Cloudflare",
    'IIS': "🪟 Windows Server (IIS)",
    'Connection': "🔌 Connection Certificate"
}

# Application types with icons
app_types = {
    'Web': "🌐 Web Application",
    'API': "🔌 API Service",
    'Service': "⚙️ Background Service",
    'Internal': "🔒 Internal Service"
}

# Export the keys for use in models
APP_TYPES = list(app_types.keys())

# Host Types
HOST_TYPE_SERVER = 'Server'
HOST_TYPE_LOAD_BALANCER = 'LoadBalancer'
HOST_TYPE_CDN = 'CDN'
HOST_TYPE_VIRTUAL = 'Virtual'

HOST_TYPES = [
    HOST_TYPE_SERVER,
    HOST_TYPE_LOAD_BALANCER,
    HOST_TYPE_CDN,
    HOST_TYPE_VIRTUAL
]

# Environments
ENV_PRODUCTION = 'Production'
ENV_CERT = 'Cert'
ENV_DEVELOPMENT = 'Development'
ENV_INTERNAL = 'Internal'
ENV_EXTERNAL = 'External'

ENVIRONMENTS = [
    ENV_PRODUCTION,
    ENV_CERT,
    ENV_DEVELOPMENT,
    ENV_INTERNAL,
    ENV_EXTERNAL
]

# Binding Types
BINDING_TYPE_IP = 'IP'
BINDING_TYPE_JWT = 'JWT'
BINDING_TYPE_CLIENT = 'Client'

BINDING_TYPES = [
    BINDING_TYPE_IP,
    BINDING_TYPE_JWT,
    BINDING_TYPE_CLIENT
]

# Platform Types
PLATFORM_F5 = 'F5'
PLATFORM_AKAMAI = 'Akamai'
PLATFORM_CLOUDFLARE = 'Cloudflare'
PLATFORM_IIS = 'IIS'
PLATFORM_CONNECTION = 'Connection'

PLATFORMS = [
    PLATFORM_F5,
    PLATFORM_AKAMAI,
    PLATFORM_CLOUDFLARE,
    PLATFORM_IIS,
    PLATFORM_CONNECTION
] 