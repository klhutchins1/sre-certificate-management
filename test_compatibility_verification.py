#!/usr/bin/env python3
"""
Compatibility Verification Test

This script tests that the Windows Python 3.8 compatibility fixes work correctly
and that SQLAlchemy can be imported without errors.
"""

import sys
import platform

def test_platform_functions():
    """Test that platform functions work correctly"""
    print("Testing platform functions...")
    
    # Test platform.machine()
    machine = platform.machine()
    print(f"✅ platform.machine() = {machine}")
    assert isinstance(machine, str), "platform.machine() should return string"
    
    # Test platform.uname()
    uname = platform.uname()
    print(f"✅ platform.uname() = {uname}")
    assert hasattr(uname, 'system'), "platform.uname() should have system attribute"
    
    # Test Windows-specific function if on Windows
    if sys.platform.startswith('win'):
        win_ver = platform.win32_ver()
        print(f"✅ platform.win32_ver() = {win_ver}")
        assert isinstance(win_ver, tuple), "platform.win32_ver() should return tuple"

def test_sqlalchemy_import():
    """Test that SQLAlchemy can be imported without errors"""
    print("\nTesting SQLAlchemy import...")
    
    # Try to import compatibility fixes (optional)
    try:
        from infra_mgmt.compatibility import ensure_compatibility
        ensure_compatibility()
        print("✅ Compatibility fixes applied")
    except ImportError as e:
        print(f"⚠️  Compatibility module not found: {e}")
        print("Continuing without explicit compatibility fixes...")
    
    # Test SQLAlchemy core imports
    from sqlalchemy import create_engine, text
    print("✅ SQLAlchemy core modules imported successfully")
    
    # Test SQLAlchemy ORM imports  
    from sqlalchemy.orm import sessionmaker, Session
    print("✅ SQLAlchemy ORM modules imported successfully")
    
    # Test creating an in-memory database
    engine = create_engine("sqlite:///:memory:")
    print("✅ SQLAlchemy engine created successfully")
    
    # Test basic query
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1 as test")).fetchone()
        assert result is not None, "Query should return a result"
        assert result[0] == 1, "Basic query should return 1"
    print("✅ Basic SQLAlchemy query works")

def main():
    """Run all compatibility tests"""
    print("=" * 60)
    print("Windows Python 3.8 Compatibility Verification")
    print("=" * 60)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print("=" * 60)
    
    # Test platform functions
    platform_ok = test_platform_functions()
    
    # Test SQLAlchemy import
    sqlalchemy_ok = test_sqlalchemy_import()
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    if platform_ok:
        print("✅ Platform functions working correctly")
    else:
        print("❌ Platform functions have issues")
    
    if sqlalchemy_ok:
        print("✅ SQLAlchemy imports and works correctly")
    else:
        print("❌ SQLAlchemy has import or functionality issues")
    
    if platform_ok and sqlalchemy_ok:
        print("\n🎉 All compatibility tests passed!")
        return True
    else:
        print("\n⚠️  Some compatibility issues detected")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)