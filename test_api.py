#!/usr/bin/env python3
"""
SecureShield Test Script - Automated API Testing
Demonstrates all requirements and security features
"""

import requests
import json
import time
import base64
from typing import Dict, Tuple

BASE_URL = "http://localhost:5000"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.YELLOW}ℹ️  {text}{Colors.END}")

def decode_jwt_payload(token: str) -> Dict:
    """Decode JWT payload (for display only)"""
    try:
        parts = token.split('.')
        payload = parts[1]
        # Add padding if necessary
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}

# Test Data
admin_token = None
user_token = None
user2_token = None
admin_user_id = None
user_id = None
user2_id = None

def test_1_register_user():
    """Task 1: Test Secure Password Storage - User Registration"""
    global user_id, user2_id
    print_header("TEST 1: Secure Password Storage - User Registration")
    
    # Test 1a: Register first user
    print_info("Registering user: 'testuser' with password 'secure123'")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "testuser",
        "password": "secure123"
    })
    
    if response.status_code == 201:
        data = response.json()
        user_id = data['user_id']
        print_success(f"User registered: ID={user_id}, Username={data['username']}, Role={data['role']}")
    else:
        print_error(f"Registration failed: {response.status_code}")
        return False
    
    # Test 1b: Register second user
    print_info("Registering user: 'normaluser' with password 'pass456'")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "normaluser",
        "password": "pass456"
    })
    
    if response.status_code == 201:
        data = response.json()
        user2_id = data['user_id']
        print_success(f"Second user registered: ID={user2_id}")
    else:
        print_error(f"Second registration failed: {response.status_code}")
        return False
    
    # Test 1c: Attempt to register duplicate username
    print_info("Attempting to register duplicate username 'testuser'...")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "testuser",
        "password": "anotherpwd"
    })
    
    if response.status_code == 409:
        print_success("Duplicate username rejected (409 Conflict)")
    else:
        print_error(f"Expected 409, got {response.status_code}")
        return False
    
    # Test 1d: Attempt to register as Admin
    print_info("Attempting to register as Admin role...")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "hacker",
        "password": "hack123",
        "role": "Admin"
    })
    
    if response.status_code == 403:
        print_success("Admin registration blocked (403 Forbidden)")
    else:
        print_error(f"Expected 403, got {response.status_code}")
        return False
    
    print_success("TEST 1 PASSED: Secure Password Storage Working\n")
    return True

def test_2_jwt_issuance():
    """Task 2: Test JWT Token Issuance"""
    global admin_token, user_token, admin_user_id
    print_header("TEST 2: JWT Issuance - Login and Token Generation")
    
    # Test 2a: Admin login
    print_info("Admin login with credentials 'admin' / 'admin123'")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "admin",
        "password": "admin123"
    })
    
    if response.status_code == 200:
        data = response.json()
        admin_token = data['token']
        admin_user_id = 1  # Default admin ID
        print_success(f"Admin login successful")
        print_info(f"Token: {admin_token[:50]}...")
        
        # Decode and display payload
        payload = decode_jwt_payload(admin_token)
        print_info(f"JWT Payload: {json.dumps(payload, indent=2)}")
        
        if payload.get('role') == 'Admin':
            print_success(f"JWT contains correct role: Admin")
        else:
            print_error(f"JWT role mismatch")
            return False
    else:
        print_error(f"Admin login failed: {response.status_code}")
        return False
    
    # Test 2b: Regular user login
    print_info("User login with credentials 'testuser' / 'secure123'")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "testuser",
        "password": "secure123"
    })
    
    if response.status_code == 200:
        data = response.json()
        user_token = data['token']
        print_success(f"User login successful")
        print_info(f"Token: {user_token[:50]}...")
        
        payload = decode_jwt_payload(user_token)
        if payload.get('role') == 'User':
            print_success(f"JWT contains correct role: User")
        else:
            print_error(f"JWT role mismatch")
            return False
    else:
        print_error(f"User login failed: {response.status_code}")
        return False
    
    # Test 2c: Invalid credentials
    print_info("Attempting login with invalid password...")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "testuser",
        "password": "wrongpassword"
    })
    
    if response.status_code == 401:
        print_success("Invalid credentials rejected (401 Unauthorized)")
    else:
        print_error(f"Expected 401, got {response.status_code}")
        return False
    
    print_success("TEST 2 PASSED: JWT Issuance Working\n")
    return True

def test_3_token_validation():
    """Task 3: Test Token Validation Middleware"""
    print_header("TEST 3: Token Validation - Protected Routes")
    
    # Test 3a: Request without token
    print_info("Accessing /profile without token...")
    response = requests.get(f"{BASE_URL}/profile")
    
    if response.status_code == 401:
        print_success("Request without token rejected (401 Unauthorized)")
    else:
        print_error(f"Expected 401, got {response.status_code}")
        return False
    
    # Test 3b: Request with valid token
    print_info("Accessing /profile with valid user token...")
    response = requests.get(f"{BASE_URL}/profile", 
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 200:
        data = response.json()
        print_success(f"Profile accessed: {data['username']} ({data['role']})")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    # Test 3c: Request with malformed token
    print_info("Attempting malformed Authorization header...")
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": "Bearer invalid.token.here"})
    
    if response.status_code == 401:
        print_success("Invalid token rejected (401 Unauthorized)")
    else:
        print_error(f"Expected 401, got {response.status_code}")
        return False
    
    # Test 3d: Request with tampered token
    print_info("Attempting to use tampered/fake token...")
    fake_token = user_token[:-10] + "tampered123"
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {fake_token}"})
    
    if response.status_code == 401:
        print_success("Tampered token rejected (401 Unauthorized)")
    else:
        print_error(f"Expected 401, got {response.status_code}")
        return False
    
    print_success("TEST 3 PASSED: Token Validation Working\n")
    return True

def test_4_role_based_routing():
    """Task 4: Test Role-Based Routing"""
    print_header("TEST 4: Role-Based Routing - Access Control")
    
    # Test 4a: User accessing profile (allowed)
    print_info("User accessing /profile (allowed for both User and Admin)...")
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 200:
        data = response.json()
        print_success(f"User profile access ALLOWED: {data['username']}")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    # Test 4b: Admin accessing profile (allowed)
    print_info("Admin accessing /profile (allowed for both User and Admin)...")
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {admin_token}"})
    
    if response.status_code == 200:
        print_success("Admin profile access ALLOWED")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    # Test 4c: Regular user attempting DELETE (forbidden)
    print_info(f"Regular user attempting to DELETE /user/{user2_id} (should be forbidden)...")
    response = requests.delete(f"{BASE_URL}/user/{user2_id}",
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 403:
        print_success(f"Regular user DELETE blocked (403 Forbidden)")
        print_info(f"Response: {response.json()['message']}")
    else:
        print_error(f"Expected 403, got {response.status_code}")
        return False
    
    # Test 4d: Admin deleting user (allowed)
    print_info(f"Admin attempting to DELETE /user/{user2_id} (should succeed)...")
    response = requests.delete(f"{BASE_URL}/user/{user2_id}",
        headers={"Authorization": f"Bearer {admin_token}"})
    
    if response.status_code == 200:
        print_success(f"Admin DELETE allowed: {response.json()['message']}")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    print_success("TEST 4 PASSED: Role-Based Routing Working\n")
    return True

def test_5_token_blacklist():
    """Task 5: Test Token Revocation (Blacklisting)"""
    print_header("TEST 5: Token Revocation - Logout and Blacklisting")
    
    # Test 5a: Access profile with token
    print_info("User accessing profile with token...")
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 200:
        print_success("Profile accessible with valid token")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    # Test 5b: Logout
    print_info("User logging out (calling /logout)...")
    response = requests.post(f"{BASE_URL}/logout",
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 200:
        print_success(f"Logout successful: {response.json()['message']}")
    else:
        print_error(f"Expected 200, got {response.status_code}")
        return False
    
    # Test 5c: Attempt to use blacklisted token
    print_info("Attempting to use blacklisted token...")
    time.sleep(1)  # Small delay
    response = requests.get(f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {user_token}"})
    
    if response.status_code == 401:
        print_success("Blacklisted token rejected (401 Unauthorized)")
        print_info(f"Response: {response.json()['message']}")
    else:
        print_error(f"Expected 401, got {response.status_code}")
        return False
    
    print_success("TEST 5 PASSED: Token Blacklisting Working\n")
    return True

def test_6_security_logging():
    """Task 6: Test Defensive Logging"""
    print_header("TEST 6: Defensive Logging - Security Log File")
    
    print_info("Checking if security.log file exists...")
    try:
        with open('security.log', 'r', encoding='utf-8') as f:
            logs = f.readlines()
            if len(logs) > 0:
                print_success(f"Security log file exists with {len(logs)} entries")
                print_info("Recent log entries:")
                for log in logs[-5:]:  # Show last 5 entries
                    print(f"  {log.strip()}")
            else:
                print_error("Security log is empty")
                return False
    except FileNotFoundError:
        print_error("security.log file not found")
        return False
    
    print_success("TEST 6 PASSED: Security Logging Working\n")
    return True

def run_all_tests():
    """Run all tests"""
    print(f"\n{Colors.BLUE}")
    print("╔" + "═"*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  SECURESHIELD - COMPREHENSIVE TEST SUITE".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "═"*58 + "╝")
    print(Colors.END)
    
    tests = [
        ("Task 1: Secure Password Storage", test_1_register_user),
        ("Task 2: JWT Issuance", test_2_jwt_issuance),
        ("Task 3: Token Validation", test_3_token_validation),
        ("Task 4: Role-Based Routing", test_4_role_based_routing),
        ("Task 5: Token Revocation", test_5_token_blacklist),
        ("Task 6: Defensive Logging", test_6_security_logging),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print_error(f"Exception in {test_name}: {str(e)}")
            failed += 1
    
    print_header("TEST SUMMARY")
    print(f"Total Tests: {len(tests)}")
    print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
    print(f"{Colors.RED}Failed: {failed}{Colors.END}")
    
    if failed == 0:
        print(f"\n{Colors.GREEN}✅ ALL TESTS PASSED!{Colors.END}\n")
    else:
        print(f"\n{Colors.RED}❌ Some tests failed. Please check the output above.{Colors.END}\n")

if __name__ == "__main__":
    try:
        # Verify server is running
        try:
            response = requests.get(f"{BASE_URL}/")
            print_success("Server is running")
        except requests.exceptions.ConnectionError:
            print_error("Cannot connect to server. Make sure Flask is running on port 5000")
            print_error("Run: venv\\Scripts\\python.exe app.py")
            exit(1)
        
        # Run tests
        run_all_tests()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test interrupted by user{Colors.END}")
        exit(0)
