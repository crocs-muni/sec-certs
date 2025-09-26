#!/usr/bin/env python3
"""
Simple test script to validate user account functionality
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Set testing environment
os.environ['TESTING'] = 'True'

try:
    from sec_certs_page import app
    
    with app.app_context():
        # Test importing admin forms
        from sec_certs_page.admin.forms import RegisterForm, PasswordResetRequestForm, PasswordResetForm
        print("✓ Forms imported successfully")
        
        # Test importing user model
        from sec_certs_page.admin.user import User
        print("✓ User model imported successfully")
        
        # Test creating a form instance
        form = RegisterForm()
        print(f"✓ RegisterForm created with fields: {list(form._fields.keys())}")
        
        # Test user model methods exist
        user_methods = [method for method in dir(User) if not method.startswith('_')]
        expected_methods = ['check_password', 'confirm_email', 'create', 'dict', 'get', 'get_by_email', 'id', 'save', 'set_password']
        missing_methods = set(expected_methods) - set(user_methods)
        if missing_methods:
            print(f"⚠ Missing methods in User model: {missing_methods}")
        else:
            print("✓ User model has all expected methods")
        
        print("\n🎉 All basic imports and structures are working!")
        print("\nNext steps:")
        print("1. Configure email settings (MAIL_SERVER, etc.)")
        print("2. Set up MongoDB connection")
        print("3. Test registration and email confirmation flow")
        print("4. Test password reset flow")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)