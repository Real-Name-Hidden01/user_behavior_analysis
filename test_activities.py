import time
import os
import subprocess
import requests
import json
import random
from datetime import datetime

def generate_test_activities():
    """Generate test activities with varying risk levels for demonstration"""
    
    print("Generating test activities with realistic risk levels...")
    
    # 1. Low risk activities (normal user behavior)
    print("1. Generating low-risk normal activities...")
    low_risk_activities = [
        {
            "user_id": "demo_user",
            "activity_type": "file_access",
            "resource": "document.pdf",
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": True
        },
        {
            "user_id": "demo_user", 
            "activity_type": "process_start",
            "resource": "notepad.exe",
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": True
        },
        {
            "user_id": "demo_user",
            "activity_type": "network_connection",
            "resource": "google.com:443",
            "ip_address": "192.168.1.100",
            "location": "Local Network", 
            "success": True
        }
    ]
    
    for activity in low_risk_activities:
        try:
            response = requests.post("http://localhost:5000/api/simulate_activity", 
                                   json=activity, timeout=5)
            if response.status_code == 200:
                result = response.json()
                print(f"  ✓ {activity['activity_type']} - Risk: {result.get('risk_score', 0)*100:.1f}%")
            time.sleep(1)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    time.sleep(2)
    
    # 2. Medium risk activities (slightly suspicious)
    print("2. Generating medium-risk activities...")
    medium_risk_activities = [
        {
            "user_id": "demo_user",
            "activity_type": "file_access", 
            "resource": "system.log",
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": False  # Failed access
        },
        {
            "user_id": "demo_user",
            "activity_type": "process_start",
            "resource": "netstat.exe", 
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": True
        },
        {
            "user_id": "demo_user",
            "activity_type": "network_connection",
            "resource": "unknown.site.com:8080",
            "ip_address": "192.168.1.100", 
            "location": "External Network",
            "success": True
        }
    ]
    
    for activity in medium_risk_activities:
        try:
            response = requests.post("http://localhost:5000/api/simulate_activity",
                                   json=activity, timeout=5)
            if response.status_code == 200:
                result = response.json()
                print(f"  ⚠ {activity['activity_type']} - Risk: {result.get('risk_score', 0)*100:.1f}%")
            time.sleep(1)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    time.sleep(2)
    
    # 3. High risk activities (suspicious behavior)
    print("3. Generating high-risk suspicious activities...")
    high_risk_activities = [
        {
            "user_id": "demo_user",
            "activity_type": "command_execution",
            "resource": "powershell.exe",
            "ip_address": "192.168.1.100",
            "location": "Local Network", 
            "success": True
        },
        {
            "user_id": "demo_user",
            "activity_type": "command_execution",
            "resource": "cmd.exe",
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": True
        },
        {
            "user_id": "demo_user",
            "activity_type": "network_connection", 
            "resource": "suspicious.domain.com:4444",
            "ip_address": "192.168.1.100",
            "location": "External Network",
            "success": True
        },
        {
            "user_id": "demo_user",
            "activity_type": "file_access",
            "resource": "passwords.txt",
            "ip_address": "192.168.1.100",
            "location": "Local Network",
            "success": False  # Multiple failed attempts
        }
    ]
    
    for activity in high_risk_activities:
        try:
            response = requests.post("http://localhost:5000/api/simulate_activity",
                                   json=activity, timeout=5)
            if response.status_code == 200:
                result = response.json() 
                print(f"  🚨 {activity['activity_type']} - Risk: {result.get('risk_score', 0)*100:.1f}%")
            time.sleep(1)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    # 4. Create and delete some files for real file monitoring
    print("4. Creating real file activities...")
    test_files = ["test_normal.txt", "test_suspicious.bat", "test_script.ps1"]
    
    for filename in test_files:
        try:
            # Create file
            with open(filename, "w") as f:
                f.write(f"Test content for {filename}")
            print(f"  📁 Created: {filename}")
            time.sleep(1)
            
            # Delete file
            if os.path.exists(filename):
                os.remove(filename)
                print(f"  🗑️ Deleted: {filename}")
            time.sleep(1)
        except Exception as e:
            print(f"  ✗ File operation error: {e}")
    
    # 5. Run some system commands to trigger process monitoring
    print("5. Running system commands for process monitoring...")
    safe_commands = [
        ["echo", "Hello UBA Demo"],
        ["dir" if os.name == 'nt' else "ls"],
        ["whoami"]
    ]
    
    for cmd in safe_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(f"  💻 Executed: {' '.join(cmd)}")
            time.sleep(2)
        except Exception as e:
            print(f"  ✗ Command error: {e}")
    
    print("\n" + "="*50)
    print("Test activities completed!")
    print("Check the UBA dashboard at http://localhost:5000")
    print("You should see:")
    print("- Low risk activities (1-20%)")
    print("- Medium risk activities (20-60%)")  
    print("- High risk activities (60-90%)")
    print("- Real-time alerts for high-risk activities")
    print("="*50)

if __name__ == "__main__":
    print("UBA Platform Advanced Activity Generator")
    print("========================================")
    print("This script generates activities with realistic risk levels:")
    print("• Low Risk: Normal user activities (1-20%)")
    print("• Medium Risk: Slightly suspicious activities (20-60%)")
    print("• High Risk: Potentially malicious activities (60-90%)")
    print()
    print("Make sure the UBA Platform is running before executing this script.")
    print()
    
    input("Press Enter to start generating test activities...")
    
    generate_test_activities()
    
    input("\nPress Enter to exit...")
