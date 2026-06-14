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
<img width="563" height="575" alt="image" src="https://github.com/user-attachments/assets/cebd556d-7abc-4416-94f8-9e26da5070b0" />

# Example when Zombie APIs are discovered:
<img width="503" height="800" alt="image" src="https://github.com/user-attachments/assets/d4ea9af2-d9e6-4af1-83e3-9106ef21de13" />
# Example with no detected Zombie APIs
<img width="505" height="582" alt="image" src="https://github.com/user-attachments/assets/09a0a941-c0d7-42ac-aa31-11296cc86e6a" />






