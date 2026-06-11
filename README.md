# ZombieAPI
Zombie APIs: Detecting Runtime‑Reachable but Deprecated Endpoints
# Abstract
Abstract—Modern networked applications expose rapidly evolving REST‑API surfaces driven by continuous integration, versioning, and frequent deployment. Existing API‑testing tools mainly target vulnerability discovery within documented interfaces and assume that the published specifications are complete. In practice, however, inconsistent enforcement of API‑lifecycle policies often leaves deprecated, undocumented, or hidden endpoints, referred to as zombie APIs, accessible at runtime. These endpoints expand the effective attack surface and violate the assumptions underlying API governance and security testing. This paper addresses that gap by formalizing zombie APIs as discrepancies between declared lifecycle states and observable runtime behavior. We propose a scalable method for discovering zombie and hidden APIs directly from a target URL without relying on full specifications. The approach combines artifact‑based endpoint extraction from client‑side resources with adaptive probing techniques, including HTTP‑method mutation, API‑version enumeration, header‑based shadow probing, and differential response analysis. To evaluate the proposed method under both realistic and controlled conditions, we deployed (i) an Internet‑facing server that emulates a production API ecosystem and (ii) local test environments built with Python and FastAPI. The system is implemented as a multithreaded C++ framework to enable efficient large‑scale scanning. Experimental results across these environments, augmented by limited validation against the GitHub REST API, demonstrate that our approach reliably identifies hidden and zombie endpoints, including undocumented interfaces that expose unintended functionality. These findings reveal a critical blind spot in existing API‑testing methodologies.
# Instructions (Building the ZombieAPI.cpp on a MacOS)
1. Download the ZombieAPI.cpp file to a folder on your Mac system,
2. Then open up a terminal window and navigate to the folder you saved the file to.
3. Finally, use the following command to make the source code executable:  
   g++ ZombieAPI.cpp -o ZombieAPI -lcurl -pthread -std=c++20
# Note: 
If you have errors compiling, make sure you have the Curl libraries installed. 
   For example: brew install curl
# Running the program (example to see usage with built-in help):
   ./ZombieAPI --help
   
# Zombie API detection workflow:
<img width="252" height="255" alt="image" src="https://github.com/user-attachments/assets/f99e4587-ceac-4174-83b4-45323a5385f9" />

# Example running all 4 modules:
./ZombieAPI http://localhost --passive-recon --header-probe --changelog-hunt --diff-fuzz  
#  
🧠 Application Version: 13.070200

🚀 Scanning: http://localhost 

🧵 Using 10 threads 

📊 Crawl depth: 1 

📦 Received 22 bytes (HTTP 404) 

🧟 ROOT URL IS AN API ENDPOINT! 

🎯 Initial endpoints found on start page: 0 

🎯 Fuzzing 16 common API paths... 

✅ Fuzzing complete. Potential APIs found: 0 

🕷️  Starting crawl from: http://localhost 

📍 Depth 0: Processing 1 URLs 

🧟 API ENDPOINT DETECTED: http://localhost (Status: 404)  

✅ Depth 0 complete. Endpoints found: 0, API responses detected: 1  

📍 Depth 1: No more URLs to crawl  
 
🔍 Endpoints found after crawl: 1  
   🧟 http://localhost  

🔎 [PassiveRecon] Starting passive hidden-endpoint discovery on: http://localhost

📄 [PassiveRecon] OpenAPI/Swagger spec found: http://localhost/openapi.json
   🧟 [NORMAL] http://localhost/analytics/products
   🧟 [NORMAL] http://localhost/analytics/revenue
   🧟 [NORMAL] http://localhost/analytics/users
   🧟 [NORMAL] http://localhost/auth/audit-logs
   🧟 [NORMAL] http://localhost/auth/login
   🧟 [NORMAL] http://localhost/auth/logout
   🧟 [NORMAL] http://localhost/config
   🧟 [SUSPECT] http://localhost/debug/echo
   🧟 [SUSPECT] http://localhost/debug/headers
   🧟 [SUSPECT] http://localhost/debug/random
   🧟 [SUSPECT] http://localhost/debug/status
   🧟 [SUSPECT] http://localhost/debug/time
   🧟 [NORMAL] http://localhost/files
   🧟 [NORMAL] http://localhost/files/large
   🧟 [NORMAL] http://localhost/files/{file_id}
   🧟 [NORMAL] http://localhost/health
   🧟 [NORMAL] http://localhost/logs
   🧟 [NORMAL] http://localhost/logs/errors
   🧟 [NORMAL] http://localhost/logs/recent
   🧟 [NORMAL] http://localhost/logs/{log_id}
   🧟 [NORMAL] http://localhost/metrics
   🧟 [NORMAL] http://localhost/notifications
   🧟 [NORMAL] http://localhost/notifications/send
   🧟 [NORMAL] http://localhost/orders
   🧟 [NORMAL] http://localhost/orders/high-value
   🧟 [NORMAL] http://localhost/orders/stats
   🧟 [NORMAL] http://localhost/orders/user/{user_id}
   🧟 [NORMAL] http://localhost/orders/{order_id}
   🧟 [NORMAL] http://localhost/products
   🧟 [NORMAL] http://localhost/products/out-of-stock
   🧟 [NORMAL] http://localhost/products/search
   🧟 [NORMAL] http://localhost/products/top
   🧟 [NORMAL] http://localhost/products/{product_id}
   🧟 [NORMAL] http://localhost/uptime
   🧟 [NORMAL] http://localhost/users
   🧟 [NORMAL] http://localhost/users/search
   🧟 [NORMAL] http://localhost/users/{user_id}
   🧟 [NORMAL] http://localhost/users/{user_id}/orders
   🧟 [NORMAL] http://localhost/users/{user_id}/stats
   🧟 [NORMAL] http://localhost/version
   
✅ [PassiveRecon] Complete. Hidden references discovered: 40

👻 [HeaderProbe] Probing 1 endpoints with manipulated routing headers...

✅ [HeaderProbe] Complete. Shadow routes detected: 0

📜 [ChangelogHunt] Probing debug/actuator/well-known paths on: http://localhost
   📜 [SUSPECT] http://localhost/version → HTTP 200
   📜 [SUSPECT] http://localhost/redoc → HTTP 200
   📜 [SUSPECT] http://localhost/metrics → HTTP 200

✅ [ChangelogHunt] Complete. Debug/internal paths responded: 3

🔬 [DiffFuzz] Establishing 404 baseline for: http://localhost
   Baseline: HTTP 404 / 22 bytes

🔬 [DiffFuzz] Probing 16 paths for fingerprint deviation...

✅ [DiffFuzz] Complete. Deviating (hidden) paths found: 0

   ZOMBIE API DISCOVERY - FINAL REPORT            

📊 SUMMARY STATISTICS
----------------------------------------
Total Endpoints Discovered:      42

Zombie APIs Detected:            0 (0%)

Suspect Endpoints Found:         7 (16%)

Normal API Endpoints:            35 (83%)


⚠️  SUSPECT ENDPOINTS (Internal/Debug Paths)
--------------------------------------------------
  🔍 http://localhost/debug/headers
  🔍 http://localhost/metrics
  🔍 http://localhost/debug/random
  🔍 http://localhost/debug/time
  🔍 http://localhost/config
  🔍 http://localhost/debug/echo
  🔍 http://localhost/debug/status

✅ NORMAL API ENDPOINTS
--------------------------------------------------
  ✓ http://localhost/redoc
  ✓ http://localhost/users/{user_id}/orders
  ✓ http://localhost/products/{product_id}
  ✓ http://localhost/products/top
  ✓ http://localhost/users
  ✓ http://localhost/products/search
  ✓ http://localhost/orders/{order_id}
  ✓ http://localhost/orders/user/{user_id}
  ✓ http://localhost/orders/stats
  ✓ http://localhost/orders
  ✓ http://localhost/logs/{log_id}
  ✓ http://localhost/users/search
  ✓ http://localhost/logs/errors
  ✓ http://localhost/version
  ✓ http://localhost/uptime
  ✓ http://localhost/logs
  ✓ http://localhost/health
  ✓ http://localhost/users/{user_id}/stats
  ✓ http://localhost/files/large
  ✓ http://localhost/users/{user_id}
  ✓ http://localhost/notifications
  ✓ http://localhost/products/out-of-stock
  ✓ http://localhost/products
  ✓ http://localhost/analytics/products
  ✓ http://localhost/auth/audit-logs
  ✓ http://localhost/files
  ✓ http://localhost/auth/login
  ✓ http://localhost/analytics/users
  ✓ http://localhost/auth/logout
  ✓ http://localhost/logs/recent
  ✓ http://localhost/orders/high-value
  ✓ http://localhost/analytics/revenue
  ✓ http://localhost/files/{file_id}
  ✓ http://localhost/notifications/send
  ✓ http://localhost

📋 SECURITY RECOMMENDATIONS
----------------------------------------
  • Audit all debug/internal endpoint access controls
  • Restrict /metrics, /config, /logs to internal use
  • Remove or secure open /redoc Swagger UI instances
  • Implement proper authentication for sensitive paths

============================================================
