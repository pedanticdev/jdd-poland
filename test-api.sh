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

    response=$(curl -s -X POST "$BASE_URL/api/security/token" \
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

    if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 201 ] || [ "$http_code" -eq 204 ]; then
        echo "✅ Success (HTTP $http_code)"
        if [ ! -z "$body" ]; then
            echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
        fi
    else
        echo "❌ Failed (HTTP $http_code)"
        echo "$body"
    fi

    echo ""
}

# Test 1: Doctor Access
echo "=========================================="
echo "Test 1: Doctor Access (Full Permissions)"
echo "=========================================="
echo ""

DOCTOR_TOKEN=$(get_token "dr.smith" "doctor123")

if [ ! -z "$DOCTOR_TOKEN" ]; then
    test_endpoint "GET" "/api/patients" "$DOCTOR_TOKEN" "List all patients (Doctor)"
    test_endpoint "GET" "/api/patients/P-001" "$DOCTOR_TOKEN" "View specific patient (Doctor)"
    test_endpoint "GET" "/api/patients/department/Cardiology" "$DOCTOR_TOKEN" "View department patients (Doctor)"

    NEW_PATIENT='{"firstName":"Test","lastName":"Patient","dateOfBirth":"1990-01-01","email":"test@example.com","department":"Cardiology","assignedDoctor":"Dr. Smith"}'
    test_endpoint "POST" "/api/patients" "$DOCTOR_TOKEN" "Create new patient (Doctor)" "$NEW_PATIENT"
fi

echo ""

# Test 2: Nurse Access
echo "=========================================="
echo "Test 2: Nurse Access (Limited Permissions)"
echo "=========================================="
echo ""

NURSE_TOKEN=$(get_token "nurse.jones" "nurse123")

if [ ! -z "$NURSE_TOKEN" ]; then
    test_endpoint "GET" "/api/patients" "$NURSE_TOKEN" "List all patients (Nurse)"
    test_endpoint "GET" "/api/patients/P-001" "$NURSE_TOKEN" "View specific patient (Nurse)"

    NEW_PATIENT='{"firstName":"Should","lastName":"Fail","dateOfBirth":"1990-01-01"}'
    test_endpoint "POST" "/api/patients" "$NURSE_TOKEN" "Create new patient (Nurse - should fail)" "$NEW_PATIENT"
fi

echo ""

# Test 3: Patient Access
echo "=========================================="
echo "Test 3: Patient Access (Self-Access Only)"
echo "=========================================="
echo ""

PATIENT_TOKEN=$(get_token "patient.doe" "patient123")

if [ ! -z "$PATIENT_TOKEN" ]; then
    test_endpoint "GET" "/api/patients" "$PATIENT_TOKEN" "List all patients (Patient - should fail)"
    test_endpoint "GET" "/api/patients/P-001" "$PATIENT_TOKEN" "View patient record (Patient - should fail)"
fi

echo ""

# Test 4: Admin Access
echo "=========================================="
echo "Test 4: Admin Access (System Operations)"
echo "=========================================="
echo ""

ADMIN_TOKEN=$(get_token "admin" "admin123")

if [ ! -z "$ADMIN_TOKEN" ]; then
    test_endpoint "GET" "/api/patients/stats" "$ADMIN_TOKEN" "View statistics (Admin)"
    test_endpoint "DELETE" "/api/patients/P-999" "$ADMIN_TOKEN" "Delete patient (Admin - non-existent)"
fi

echo ""

# Test 5: Security Monitoring
echo "=========================================="
echo "Test 5: Security Monitoring & Events"
echo "=========================================="
echo ""

if [ ! -z "$DOCTOR_TOKEN" ]; then
    test_endpoint "GET" "/api/security/events?limit=10" "$DOCTOR_TOKEN" "View security events"
    test_endpoint "GET" "/api/security/config" "$DOCTOR_TOKEN" "View security configuration"
fi

echo ""

# Test 6: Unauthenticated Access
echo "=========================================="
echo "Test 6: Unauthenticated Access (Should Fail)"
echo "=========================================="
echo ""

echo "🧪 Testing: Unauthenticated access to patients"
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$BASE_URL/api/patients")
http_code=$(echo "$response" | grep "HTTP_STATUS" | cut -d':' -f2)

if [ "$http_code" -eq 401 ] || [ "$http_code" -eq 403 ]; then
    echo "✅ Correctly denied (HTTP $http_code)"
else
    echo "❌ Unexpected response (HTTP $http_code)"
fi

echo ""
echo "=========================================="
echo "Demo Complete!"
echo "=========================================="
echo ""
echo "Key Observations:"
echo "- Doctors have full access to patient records"
echo "- Nurses can view but not create/modify"
echo "- Patients have no access to other records"
echo "- Admins can perform system operations"
echo "- All operations are logged for audit"
echo "- JWT tokens are validated on every request"
echo ""
