#!/bin/bash

# Check if python3 is installed, if not, install it
if ! command -v python3 &> /dev/null; then
    echo "python3 is not installed. Installing..."
    sudo dnf install -y python3
fi

# Check if pip is installed, if not, install it
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not installed. Installing..."
    sudo dnf install -y python3-pip
fi

# Check if venv is available
if ! python3 -m venv --help &> /dev/null; then
    echo "venv module is not available. Installing..."
    sudo dnf install -y python3-virtualenv
fi

# Create a virtual environment in the current directory
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "Virtual environment '.venv' created."
else
    echo "Virtual environment '.venv' already exists."
fi

# Activate the virtual environment
source .venv/bin/activate

# Install necessary packages from requirements.txt if it exists
if [ -f requirements.txt ]; then
    echo "Installing packages from requirements.txt..."
    pip install -r requirements.txt || {
        echo "Error: Failed to install some packages."
        exit 1
    }
fi
export PYTHONPATH=$(pwd)

# Ensure the environment stays activated
echo "Virtual environment initialized and activated."

echo "PYTHONPATH set to: $PYTHONPATH"