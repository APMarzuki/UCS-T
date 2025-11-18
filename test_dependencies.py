#!/usr/bin/env python3
"""
Test UCS-T Dependencies
"""

import sys


def test_imports():
    """Test all required imports"""
    imports = [
        'PyQt6',
        'requests',
        'cryptography',
        'whois',
        'dns',
        'json',
        'pathlib'
    ]

    print("🔧 Testing UCS-T Dependencies...")
    print("=" * 50)

    for package in imports:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError as e:
            print(f"❌ {package}: {e}")

    print("=" * 50)


def test_core_modules():
    """Test core module imports"""
    print("\n🔧 Testing Core Modules...")
    print("=" * 50)

    core_modules = [
        'core.api_config',
        'core.config_manager',
        'core.logger',
        'core.utils'
    ]

    for module in core_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")

    print("=" * 50)


if __name__ == "__main__":
    test_imports()
    test_core_modules()

    print("\n🎯 Next steps:")
    print("1. Run: pip install cryptography")
    print("2. Run: python app.py")