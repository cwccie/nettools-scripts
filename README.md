# Nettools Management Scripts

A collection of scripts to set up, diagnose, and fix the nettools network packet capture tool. This repository contains all the scripts needed to manage a nettools installation from start to finish.

## Quick Start

The easiest way to get started is to download and run the wrapper script:

```bash
curl -O https://github.com/cwccie/nettools-scripts/blob/main/run_nettools.sh
sudo chmod +x run_nettools.sh
sudo ./run_nettools.sh
```

This script will clone this repository and guide you through the available options.

## Scripts Overview

### run_nettools.sh

The main wrapper script that serves as an entry point for all nettools management operations. It:
- Clones or updates this repository
- Provides a menu to select the operation you want to perform
- Runs the appropriate script with sudo permissions

### nettools_setup.sh

Performs a complete fresh installation of nettools with all fixes already applied. This script:
- Updates system packages
- Installs required dependencies
- Creates the nettools user and group
- Sets up the directory structure
- Configures Python virtual environment
- Installs Python packages
- Creates all required files and configurations
- Sets appropriate permissions
- Configures and starts the systemd service

### nettools_diagnostics.sh

Generates a comprehensive diagnostic report for an existing nettools installation. This script:
- Checks system information (OS, resources, network configuration)
- Verifies service status
- Examines logs and processes
- Tests firewall configuration
- Analyzes directory structure and permissions
- Validates Python environment
- Tests network connectivity
- Provides recommendations for fixing issues

### nettools_fix_all.sh

Fixes common issues with an existing nettools installation. This script:
- Corrects initialization problems in app/__init__.py
- Fixes run.py for proper error handling
- Ensures start_nettools.sh is properly configured
- Updates the systemd service configuration
- Creates any missing directories
- Adds missing modules if needed
- Corrects file permissions and ownership
- Configures firewall rules if needed
- Restarts the service

## Requirements

- Ubuntu or Debian-based Linux distribution (other distributions may work but are not tested)
- Root access (sudo)
- Git (installed automatically if missing)
- Internet connection (for initial setup)

## Installation Directory

All scripts install nettools to `/opt/nettools`, regardless of where you run them from. You can run the scripts from any directory, and they will still set up or modify the application in the correct location.

## Usage

### Fresh Installation

```bash
# Make all scripts executable first
chmod +x *.sh

# Option 1: Using the wrapper script (recommended)
./run_nettools.sh
# Then select option 1 from the menu

# Option 2: Running the setup script directly
sudo ./nettools_setup.sh
```

### Diagnostics

```bash
# Option 1: Using the wrapper script (recommended)
./run_nettools.sh
# Then select option 2 from the menu

# Option 2: Running the diagnostics script directly
chmod +x nettools_diagnostics.sh
sudo ./nettools_diagnostics.sh [output_file]
```

If `output_file` is not specified, the report will be saved to `nettools_diagnostics_report.txt` in the current directory.

### Fixing Issues

```bash
# Option 1: Using the wrapper script (recommended)
./run_nettools.sh
# Then select option 3 from the menu

# Option 2: Running the fix script directly
chmod +x nettools_fix_all.sh
sudo ./nettools_fix_all.sh
```

## After Installation

After a successful installation, the nettools application will be accessible at:

```
http://your-server-ip:5000
```

The service will be managed by systemd:

```bash
# Start the service
sudo systemctl start nettools.service

# Stop the service
sudo systemctl stop nettools.service

# Check status
sudo systemctl status nettools.service

# View logs
sudo journalctl -u nettools.service -f
```

## Troubleshooting

If you encounter issues:

1. Run the diagnostics script to generate a detailed report
2. Check the application logs: `/opt/nettools/logs/`
3. Check the systemd service logs: `sudo journalctl -u nettools.service -f`
4. Try running the fix script to address common issues
5. If problems persist, you can run the application manually: `sudo -u nettools_user /opt/nettools/start_nettools.sh`

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
