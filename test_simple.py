#!/usr/bin/env python3
"""
Simple test to check if our forms are syntactically correct
"""
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    # Test forms syntax
    from sec_certs_page.admin.forms import (
        LoginForm, RegisterForm, PasswordResetRequestForm, PasswordResetForm, ConfigEditForm
    )
    print("✓ All forms imported successfully")
    
    # Test creating form instances (without Flask app context)
    from wtforms import Form
    
    # Simple test of form structure
    print(f"✓ RegisterForm fields: {list(RegisterForm()._fields.keys())}")
    print(f"✓ PasswordResetRequestForm fields: {list(PasswordResetRequestForm()._fields.keys())}")
    print(f"✓ PasswordResetForm fields: {list(PasswordResetForm()._fields.keys())}")
    
    print("\n🎉 Forms are syntactically correct!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)