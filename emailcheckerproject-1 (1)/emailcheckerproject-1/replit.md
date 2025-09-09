# Email Checker Application

## Overview

This is a web-based email checker tool designed to validate and test email credentials across multiple email providers. The application consists of a React frontend for user interaction and a Python Flask backend that handles email validation through various protocols (POP3, IMAP, SMTP). The system supports bulk email checking with proxy support, multi-threading for performance, and encrypted credential storage for security.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Technology Stack**: React 19.1.1 with TypeScript, built using Vite as the bundler
- **UI Framework**: Custom React components with Lucide React icons for visual elements
- **Development Setup**: Vite dev server configured to run on port 5000 with host binding for external access
- **Component Structure**: Single-page application with a main EmailChecker component handling all functionality

### Backend Architecture
- **Framework**: Flask with CORS enabled for cross-origin requests
- **Database**: SQLite3 for local data storage (accounts, results, configuration)
- **Concurrency**: Multi-threading implementation using Python's threading and queue modules for parallel email checking
- **Security**: Cryptography-based encryption (Fernet) for password storage with SHA256 key derivation
- **Protocol Support**: Multiple email protocols (POP3, IMAP, SMTP) with SSL/TLS support

### Email Provider Integration
- **Supported Providers**: Gmail, Hotmail, Outlook, Yahoo, AOL, iCloud, and custom providers
- **Configuration**: Hardcoded provider settings with IMAP/POP3/SMTP server details
- **Authentication**: Support for standard username/password and OAuth-based authentication flows

### Proxy Support
- **Types Supported**: SOCKS4, SOCKS5, HTTP, HTTPS proxies
- **Implementation**: PySocks library for proxy handling with random proxy rotation
- **Configuration**: User-configurable proxy lists with protocol selection

### Data Processing
- **Bulk Operations**: Support for processing large lists of email:password combinations
- **Statistics Tracking**: Real-time counters for loaded, checked, valid, and invalid accounts
- **Export Functionality**: Results export to various formats for further analysis

## External Dependencies

### Backend Dependencies
- **Flask & Flask-CORS**: Web framework and cross-origin resource sharing
- **Cryptography**: Encryption and security functions for credential protection
- **DNSPython**: DNS resolution for email server discovery and validation
- **PySocks**: SOCKS proxy support for network requests
- **Requests**: HTTP client library for API integrations
- **Email Protocol Libraries**: Built-in Python libraries (poplib, imaplib, smtplib) for email server communication

### Frontend Dependencies
- **React & React-DOM**: Core React framework for UI rendering
- **TypeScript**: Type safety and development tooling
- **Vite**: Fast build tool and development server
- **Lucide React**: Icon library for UI elements

### Development Tools
- **Semgrep**: Static analysis security scanning with custom rules configuration
- **Environment Variables**: SECRET_KEY for encryption key management in production

### Network Services
- **DNS Resolution**: Real-time DNS queries for email server discovery
- **Email Servers**: Direct connections to email provider servers (Gmail, Outlook, Yahoo, etc.)
- **Proxy Networks**: Optional proxy server integration for anonymized connections
- **HTTP APIs**: Configurable HTTP request capabilities for custom integrations