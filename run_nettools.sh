#!/bin/bash
#
# run_nettools.sh - Main wrapper script for nettools management
#
# This script serves as an entry point for setting up, diagnosing, and fixing the nettools application.
# It clones or updates the nettools-scripts repository and runs the appropriate script based on user choice.
#
# Usage: bash run_nettools.sh
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}     nettools Management Script                          ${NC}"
echo -e "${BLUE}     $(date)                                             ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}Git is not installed. Installing git...${NC}"
    sudo apt-get update
    sudo apt-get install -y git
fi

# Repository URL
REPO_URL="https://github.com/cwccie/nettools-scripts.git"

# Clone or update repository
if [ ! -d "nettools-scripts" ]; then
    echo -e "${YELLOW}Cloning nettools-scripts repository...${NC}"
    git clone $REPO_URL
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to clone repository. Please check your internet connection and the repository URL.${NC}"
        exit 1
    fi
    cd nettools-scripts
else
    echo -e "${YELLOW}Updating nettools-scripts repository...${NC}"
    cd nettools-scripts
    git pull
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Warning: Failed to update repository. Continuing with existing scripts.${NC}"
    fi
fi

# Make scripts executable
echo -e "${YELLOW}Setting script permissions...${NC}"
chmod +x nettools_setup.sh nettools_diagnostics.sh nettools_fix_all.sh

# Present options
echo -e "\n${GREEN}What would you like to do?${NC}"
echo -e "1) ${YELLOW}Fresh installation of nettools${NC}"
echo -e "2) ${YELLOW}Run diagnostics on existing installation${NC}"
echo -e "3) ${YELLOW}Fix existing installation${NC}"
echo -e "4) ${YELLOW}Exit${NC}"

read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo -e "\n${GREEN}Starting fresh installation of nettools...${NC}"
        sudo bash nettools_setup.sh
        ;;
    2)
        echo -e "\n${GREEN}Running diagnostics on nettools...${NC}"
        sudo bash nettools_diagnostics.sh
        ;;
    3)
        echo -e "\n${GREEN}Fixing existing nettools installation...${NC}"
        sudo bash nettools_fix_all.sh
        ;;
    4)
        echo -e "\n${GREEN}Exiting...${NC}"
        exit 0
        ;;
    *)
        echo -e "\n${RED}Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac

echo -e "\n${GREEN}Operation completed!${NC}"
echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}     nettools Management Complete                        ${NC}"
echo -e "${BLUE}=========================================================${NC}"