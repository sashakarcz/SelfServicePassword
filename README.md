# LDAP Self-Service Portal

A modern, secure web application that allows users to manage their LDAP accounts, update passwords, and configure SSH keys with multi-factor authentication support.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)
![Vue.js](https://img.shields.io/badge/Vue.js-3-4FC08D?style=flat&logo=vue.js&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## ✨ Features

### 🔐 Authentication & Security
- **LDAP Integration**: Full support for FreeIPA and standard LDAP servers
- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **Multi-factor Authentication**: Email and SMS verification for password resets
- **Password Policy Enforcement**: Configurable complexity requirements

### 🛠 User Management
- **Password Reset**: Self-service password reset via email or SMS verification
- **SSH Key Management**: Add, view, and delete SSH public keys
- **Profile Management**: View and manage user profile information
- **Session Management**: Secure session handling with automatic logout

### 🎨 Modern Interface
- **Material Design**: Clean, responsive UI built with Vue.js 3
- **Dark/Light Mode**: Toggle between themes with user preference persistence
- **Mobile Responsive**: Optimized for desktop, tablet, and mobile devices
- **Real-time Feedback**: Instant validation and status updates
- **Custom Branding**: Configurable site names and security-themed favicon

### 📱 Communication
- **Email Notifications**: SMTP support for password reset notifications
- **SMS Integration**: Apprise API integration with VoIP.ms and other providers
- **Configurable Templates**: Customizable message templates

### 🔧 Administration
- **Docker Support**: Complete containerization with Docker and docker-compose
- **Configurable Branding**: Custom site names, logos, and themes
- **Comprehensive Logging**: Structured logging with configurable levels
- **Health Monitoring**: Built-in health checks and metrics

## Quick Start

### Using Docker Compose

1. Clone the repository:
```bash
git clone <repository-url>
cd ldap-self-service
```

2. The application is pre-configured for your Starnix environment in `config.yaml`:
```yaml
ldap:
  host: "192.168.1.24"
  port: 389
  bind_dn: "uid=sspr,cn=users,cn=accounts,dc=starnix,dc=net"
  bind_password: "astrognome1007"
  user_base_dn: "cn=users,cn=accounts,dc=starnix,dc=net"

email:
  smtp_host: "smtp.gmail.com"
  smtp_user: "info@starnix.net"
  from_email: "info@starnix.net"
  from_name: "Starnix Self Service Password"
```

3. Start the application:
```bash
docker-compose up -d
```

4. Access the application at `http://localhost:8080`

### Manual Installation

1. Install Go 1.21 or later
2. Install dependencies:
```bash
go mod download
```

3. Configure the application (see config.yaml)
4. Run the application:
```bash
go run main.go
```

## Configuration

The application uses a YAML configuration file (`config.yaml`) with the following sections:

### LDAP Configuration
```yaml
ldap:
  host: "localhost"
  port: 389
  use_tls: false
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  bind_password: "admin"
  user_filter: "(uid=%s)"
  user_base_dn: "ou=people,dc=example,dc=com"
  ssh_key_attr: "sshPublicKey"
  email_attr: "mail"
  phone_attr: "mobile"
```

### Email Configuration
```yaml
email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_user: "your-email@gmail.com"
  smtp_password: "your-app-password"
  from_email: "your-email@gmail.com"
  from_name: "LDAP Self-Service"
```

### SMS Configuration
```yaml
sms:
  provider: "mock"  # Options: mock, twilio
  api_key: ""
  api_secret: ""
  from_phone: "+1234567890"
```

## LDAP Schema Requirements

The application expects the following LDAP attributes:

- `uid`: Username for authentication
- `mail`: Email address for notifications
- `mobile`: Phone number for SMS verification
- `sshPublicKey`: SSH public keys (multi-valued attribute)
- `givenName`: First name
- `sn`: Last name

### Adding SSH Key Support to OpenLDAP

If your LDAP server doesn't support SSH keys, add this schema:

```ldif
dn: cn=openssh,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey'
  DESC 'MANDATORY: OpenSSH Public key'
  EQUALITY octetStringMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey'
  SUP top AUXILIARY
  DESC 'MANDATORY: OpenSSH LPK objectclass'
  MAY ( sshPublicKey $ uid ) )
```

## API Endpoints

### Authentication
- `POST /api/v1/login` - User login
- `POST /api/v1/verify-email` - Email verification
- `POST /api/v1/verify-sms` - SMS verification

### User Management (Authenticated)
- `GET /api/v1/profile` - Get user profile
- `PUT /api/v1/password` - Update password
- `GET /api/v1/ssh-keys` - Get SSH keys
- `POST /api/v1/ssh-keys` - Add SSH key
- `DELETE /api/v1/ssh-keys/:id` - Remove SSH key

## Security Features

- JWT-based authentication
- Password strength validation
- SSH key format validation
- Rate limiting (configurable)
- CORS protection
- Secure session management
- TLS support for LDAP connections

## Development

### Project Structure
```
├── cmd/                    # Application entrypoints
├── internal/
│   ├── config/            # Configuration management
│   ├── handlers/          # HTTP handlers
│   ├── middleware/        # HTTP middleware
│   ├── models/           # Data models
│   └── services/         # Business logic
├── web/
│   ├── static/           # Static assets (CSS, JS)
│   └── templates/        # HTML templates
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile           # Container definition
└── config.yaml         # Application configuration
```

### Building from Source

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build binary
go build -o ldap-self-service main.go

# Run
./ldap-self-service
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

For issues and questions:
- Check the GitHub issues
- Review the configuration documentation
- Ensure your LDAP schema includes required attributes