#!/bin/bash

# Zero Trust Healthcare API Demo Script
# Tests authentication, authorization, and audit logging

set -e

BASE_URL="http://localhost:8080"
KEYCLOAK_URL="http://localhost:8180"
REALM="jdd-poland"

echo "=========================================="
echo "Zero Trust Healthcare API Demo"
echo "=========================================="
echo ""

# Function to get token
get_token() {
    local username=$1
    local password=$2

    echo "🔑 Getting token for user: $username"

    response=$(curl -s -X POST "$BASE_URL/resources/security/token" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}")

    token=$(echo $response | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

    if [ -z "$token" ]; then
        echo "❌ Failed to get token for $username"
        echo "Response: $response"
        return 1
    fi

    echo "✅ Token obtained successfully"
    echo ""
    echo $token
}

# Function to test API endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local token=$3
    local description=$4
    local data=$5
    local expected_status=("200" "201" "204") # Default expected success codes

    # Allow overriding expected status
    if [[ $6 ]]; then
        expected_status=($6)
    fi

    echo "🧪 Testing: $description"
    echo "   $method $endpoint"

    if [ -z "$data" ]; then
        response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json")
    else
        response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi

    http_code=$(echo "$response" | grep "HTTP_STATUS" | cut -d':' -f2)
    body=$(echo "$response" | sed '/HTTP_STATUS/d')

    # Check if http_code is in the array of expected status codes
    if [[ " ${expected_status[@]} " =~ " ${http_code} " ]]; then
        echo "✅ Success (HTTP $http_code)"
        if [ ! -z "$body" ]; then
            echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
        fi
    else
        echo "❌ Failed (HTTP $http_code) - Expected one of: ${expected_status[*]}"
        echo "$body"
    fi

    echo ""
}

# Test 1: Doctor Access (dr.smith, Cardiology)
echo "=========================================="
echo "Test 1: Doctor Access (Cardiology Dept)"
echo "=========================================="
echo ""

DOCTOR_TOKEN=$(get_token "dr.smith" "doctor123")

if [ ! -z "$DOCTOR_TOKEN" ]; then
    test_endpoint "GET" "/resources/patients" "$DOCTOR_TOKEN" "List all patients (Doctor - should fail)" "403"
    test_endpoint "GET" "/resources/patients/P-001" "$DOCTOR_TOKEN" "View specific patient (Doctor)"
    test_endpoint "GET" "/resources/patients/department/Cardiology" "$DOCTOR_TOKEN" "View own department patients (Doctor - should succeed)"
    test_endpoint "GET" "/resources/patients/department/Emergency" "$DOCTOR_TOKEN" "View OTHER department patients (Doctor - should fail)" "403"

    NEW_PATIENT='{"firstName":"Test","lastName":"Patient","dateOfBirth":"1990-01-01","email":"test@example.com","department":"Cardiology","assignedDoctor":"Dr. Smith"}'
    test_endpoint "POST" "/resources/patients" "$DOCTOR_TOKEN" "Create new patient (Doctor)" "$NEW_PATIENT" "201"
fi

echo ""

# Test 2: Nurse Access (nurse.jones, Emergency)
echo "=========================================="
echo "Test 2: Nurse Access (Emergency Dept)"
echo "=========================================="
echo ""

NURSE_TOKEN=$(get_token "nurse.jones" "nurse123")

if [ ! -z "$NURSE_TOKEN" ]; then
    test_endpoint "GET" "/resources/patients" "$NURSE_TOKEN" "List all patients (Nurse - should fail)" "403"
    test_endpoint "GET" "/resources/patients/P-003" "$NURSE_TOKEN" "View specific patient (Nurse)"
    test_endpoint "GET" "/resources/patients/department/Emergency" "$NURSE_TOKEN" "View own department patients (Nurse - should succeed)"
    test_endpoint "GET" "/resources/patients/department/Cardiology" "$NURSE_TOKEN" "View OTHER department patients (Nurse - should fail)" "403"

    NEW_PATIENT='{"firstName":"Should","lastName":"Fail","dateOfBirth":"1990-01-01"}'
    test_endpoint "POST" "/resources/patients" "$NURSE_TOKEN" "Create new patient (Nurse - should fail)" "$NEW_PATIENT" "403"
fi

echo ""

# Test 3: Patient Access
echo "=========================================="
echo "Test 3: Patient Access (Self-Access Only)"
echo "=========================================="
echo ""

PATIENT_TOKEN=$(get_token "patient.doe" "patient123")

if [ ! -z "$PATIENT_TOKEN" ]; then
    test_endpoint "GET" "/resources/patients" "$PATIENT_TOKEN" "List all patients (Patient - should fail)" "403"
    test_endpoint "GET" "/resources/patients/P-001" "$PATIENT_TOKEN" "View patient record (Patient - should fail)" "403"
fi

echo ""

# Test 4: Admin Access
echo "=========================================="
echo "Test 4: Admin Access (System Operations)"
echo "=========================================="
echo ""

ADMIN_TOKEN=$(get_token "admin" "admin123")

if [ ! -z "$ADMIN_TOKEN" ]; then
    test_endpoint "GET" "/resources/patients" "$ADMIN_TOKEN" "List all patients (Admin - should succeed)"
    test_endpoint "GET" "/resources/patients/stats" "$ADMIN_TOKEN" "View statistics (Admin)"
    test_endpoint "DELETE" "/resources/patients/P-005" "$ADMIN_TOKEN" "Delete patient (Admin - should succeed)" "204"
fi

echo ""

# Test 5: Security Monitoring
echo "=========================================="
echo "Test 5: Security Monitoring & Events"
echo "=========================================="
echo ""

if [ ! -z "$ADMIN_TOKEN" ]; then
    test_endpoint "GET" "/resources/security/events?limit=20" "$ADMIN_TOKEN" "View security events (Admin)"
    test_endpoint "GET" "/resources/security/config" "$ADMIN_TOKEN" "View security configuration (Admin)"
fi

echo ""

# Test 6: Unauthenticated Access
echo "=========================================="
echo "Test 6: Unauthenticated Access"
echo "=========================================="
echo ""

test_endpoint "GET" "/resources/patients" "" "Access patients (No Token - should fail)" "401"
test_endpoint "GET" "/resources/patients/stats" "" "Access stats (No Token - should fail)" "401"

echo ""
echo "=========================================="
echo "Demo Complete!"
echo "=========================================="
echo ""
echo "Key Observations:"
echo "- Roles are enforced: Admins can list all patients, but Doctors/Nurses cannot."
echo "- Attributes are enforced: Doctors/Nurses can only view patients in their own department."
echo "- Permissions are granular: Nurses can view patients but cannot create them."
echo "- All operations are logged for audit (see /resources/security/events)."
echo "- Standard MicroProfile JWT and Jakarta Security APIs handle all validation."
echo ""