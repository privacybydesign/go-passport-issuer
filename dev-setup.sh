#!/bin/bash
# Development environment setup script for go-passport-issuer
# This script configures the environment variables needed to build and test the project locally

# Check if we're on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Check if ImageMagick 6 is installed via Homebrew
    if ! brew list imagemagick@6 &>/dev/null; then
        echo "ImageMagick 6 is not installed. Installing..."
        brew install imagemagick@6
    fi

    # Set environment variables for ImageMagick 6 on macOS
    export PKG_CONFIG_PATH="/opt/homebrew/opt/imagemagick@6/lib/pkgconfig"
    export CGO_CFLAGS_ALLOW="-Xpreprocessor"

    echo "✓ Environment configured for macOS with ImageMagick 6"
    echo "  PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    echo "  CGO_CFLAGS_ALLOW=$CGO_CFLAGS_ALLOW"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # For Linux, check if ImageMagick is installed
    if ! pkg-config --exists MagickWand; then
        echo "ImageMagick development libraries not found."
        echo "Please install them:"
        echo "  Ubuntu/Debian: sudo apt-get install libmagickwand-dev"
        echo "  Fedora/RHEL: sudo dnf install ImageMagick-devel"
        exit 1
    fi

    echo "✓ Environment configured for Linux"
fi

echo ""
echo "You can now run:"
echo "  cd backend && go test ./..."
echo "  cd backend && go run ."
