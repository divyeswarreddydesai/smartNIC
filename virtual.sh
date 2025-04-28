#!/bin/bash

# Disable 'exit on error' for better error handling
set +e  # Disable exit on error to keep SSH connection open
set -o pipefail  # Catch errors in piped commands

# Detect package manager
detect_package_manager() {
    if command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v apt &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    else
        echo "none"
    fi
}

# Detect OS version
detect_os_version() {
    if [ -f /etc/centos-release ]; then
        grep -q "7\." /etc/centos-release && echo "centos7" && return
    fi
    echo "other"
}

PKG_MANAGER=$(detect_package_manager)
OS_VERSION=$(detect_os_version)

if [ "$PKG_MANAGER" = "none" ]; then
    echo "❌ No supported package manager found (dnf, apt, yum). Exiting."
    exit 1
fi

echo "ℹ️  Using package manager: $PKG_MANAGER"

# If OS is CentOS 7, fix the repo
if [ "$OS_VERSION" = "centos7" ]; then
    echo "🔧 Updating CentOS 7 repo..."
    sudo curl -o /etc/yum.repos.d/CentOS-Base.repo https://el7.repo.almalinux.org/centos/CentOS-Base.repo
    sudo yum clean all
    sudo yum makecache
fi

echo "⚙️ Installing build dependencies..."
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt update
    sudo apt install -y build-essential gcc libssl-dev zlib1g-dev libbz2-dev \
        libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libgdbm-dev \
        libnss3-dev libffi-dev liblzma-dev tk-dev
else
    sudo "$PKG_MANAGER" install -y gcc openssl-devel bzip2-devel libffi-devel \
        readline-devel sqlite-devel wget curl ncurses-devel gdbm-devel nss-devel \
        lzma-sdk-devel tk-devel
fi

# Install Python 3.9 if missing
if ! command -v python3.9 &> /dev/null; then
    echo "🐍 python3.9 not found. Building from source..."

    cd /usr/src
    sudo wget https://www.python.org/ftp/python/3.9.7/Python-3.9.7.tgz
    sudo tar xzf Python-3.9.7.tgz
    cd Python-3.9.7

    sudo ./configure --enable-optimizations
    sudo make altinstall

    echo "✅ Python 3.9 installed successfully."

    # ➡️ Fix shared libraries for Python 3.9
    echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/python3.9.conf
    sudo ldconfig
else
    echo "✅ python3.9 already installed."
fi

# Fix PATH if /usr/local/bin is missing
if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
    export PATH="/usr/local/bin:$PATH"
fi

# Check if venv module works
if ! python3.9 -m venv --help &> /dev/null; then
    echo "❌ Python 3.9 venv module not available."
    exit 1
fi

# Ensure we are in the correct directory to create the .venv
cd "$(pwd)" || {
    echo "❌ Failed to navigate to the current directory. Exiting."
    exit 1
}

# Delete .venv if it exists, then create a fresh virtual environment
if [ -d ".venv" ]; then
    echo "🔧 .venv directory exists. Deleting it..."
    rm -rf .venv
    echo "✅ Deleted existing .venv directory."
fi

# Create virtual environment with python3.9 in the current directory
python3.9 -m venv .venv
echo "✅ Virtual environment '.venv' created with Python 3.9."

# Activate virtual environment
source .venv/bin/activate || {
    echo "❌ Failed to activate virtual environment. Exiting."
    exit 1
}
echo "✅ Virtual environment activated."

echo "🔍 Checking Python version..."
PYTHON_VERSION=$(python --version 2>&1)
if [[ "$PYTHON_VERSION" == *"Python 3.9"* ]]; then
    echo "✅ Python version is 3.9."
else
    echo "❌ Python version is not 3.9. Found: $PYTHON_VERSION"
    deactivate
    exit 1
fi

# Upgrade pip inside venv
pip install --upgrade pip setuptools wheel

# Install packages if requirements.txt exists
if [ -f requirements.txt ]; then
    echo "📦 Installing packages from requirements.txt..."
    pip install -r requirements.txt || {
        echo "❌ Error: Failed to install some packages."
        deactivate
        exit 1
    }
else
    echo "⚠️  No requirements.txt found. Skipping package installation."
fi

# Set PYTHONPATH
export PYTHONPATH=$(pwd)
echo "✅ PYTHONPATH set to: $PYTHONPATH"

echo "🎉 Virtual environment setup complete."
