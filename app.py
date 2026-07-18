from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import logging
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import pickle
import os
from collections import defaultdict, deque
import uuid
import psutil
import socket
import getpass
import platform
import subprocess
import requests
import hashlib
from pathlib import Path
import re
# Removed Windows-specific imports to avoid compatibility issues

# Configure logging to suppress warnings
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress deprecation warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables for real-time monitoring
user_sessions = {}
active_connections = {}
anomaly_detector = None
user_profiles = {}
activity_buffer = deque(maxlen=10000)
current_user = getpass.getuser()
current_machine = platform.node()

class RealTimeSystemMonitor:
    def __init__(self):
        self.running = False
        self.processes_cache = {}
        self.network_connections = set()
        self.file_access_monitor = {}
        self.login_events = deque(maxlen=1000)
        self.process_events = deque(maxlen=1000)
        self.network_events = deque(maxlen=1000)
        self.file_events = deque(maxlen=1000)
        
    def get_current_user_info(self):
        """Get current user information"""
        try:
            return {
                'username': getpass.getuser(),
                'machine': platform.node(),
                'os': platform.system(),
                'os_version': platform.version(),
                'ip_address': self.get_local_ip(),
                'session_id': os.environ.get('SESSIONNAME', 'Console')
            }
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return {}
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to a remote server to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_geolocation(self, ip_address):
        """Get approximate location from IP (cached to avoid delays)"""
        # Use simple local/network detection to avoid API delays during startup
        if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.') or ip_address == '127.0.0.1':
            return "Local Network"
        else:
            return "External Network"
    
    def monitor_processes(self):
        """Monitor running processes and detect new/terminated processes"""
        try:
            current_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'exe', 'cmdline'])}
            
            # Detect new processes
            for pid, info in current_processes.items():
                if pid not in self.processes_cache:
                    # New process detected
                    try:
                        activity = UserActivity(
                            user_id=current_user,
                            timestamp=datetime.now(),
                            activity_type="process_start",
                            resource=info.get('name', 'Unknown'),
                            ip_address="127.0.0.1",
                            user_agent=f"Process: {info.get('name', 'Unknown')}",
                            location="Local Network",
                            success=True,
                            session_id=str(uuid.uuid4())
                        )
                        
                        # Check for suspicious processes and set initial risk
                        initial_risk = 0.0
                        if self.is_suspicious_process(info):
                            initial_risk = 0.6  # Medium-high risk for suspicious processes
                        else:
                            initial_risk = 0.1  # Low risk for normal processes
                        
                        activity.risk_score = initial_risk
                        
                        monitor_user_activity(activity)
                        self.process_events.append(activity)
                        
                    except Exception as e:
                        logger.error(f"Error monitoring process {pid}: {e}")
            
            # Detect terminated processes
            for pid in list(self.processes_cache.keys()):
                if pid not in current_processes:
                    # Process terminated
                    try:
                        info = self.processes_cache[pid]
                        activity = UserActivity(
                            user_id=current_user,
                            timestamp=datetime.now(),
                            activity_type="process_end",
                            resource=info.get('name', 'Unknown'),
                            ip_address="127.0.0.1",
                            user_agent=f"Process: {info.get('name', 'Unknown')}",
                            location="Local Network",
                            success=True,
                            session_id=str(uuid.uuid4())
                        )
                        
                        monitor_user_activity(activity)
                        
                    except Exception as e:
                        logger.error(f"Error monitoring terminated process {pid}: {e}")
            
            self.processes_cache = current_processes
            
        except Exception as e:
            logger.error(f"Error in process monitoring: {e}")
    
    def is_suspicious_process(self, process_info):
        """Check if a process is potentially suspicious"""
        suspicious_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
            'bitsadmin.exe', 'netsh.exe', 'sc.exe', 'taskkill.exe',
            'net.exe', 'whoami.exe', 'systeminfo.exe'
        ]
        
        process_name = process_info.get('name', '').lower()
        process_path = process_info.get('exe', '').lower() if process_info.get('exe') else ''
        
        # Check for suspicious process names
        if process_name in suspicious_names:
            return True
        
        # Check for processes running from temp directories
        temp_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\']
        if any(temp_path in process_path for temp_path in temp_paths):
            return True
        
        return False
    
    def monitor_network_connections(self):
        """Monitor network connections"""
        try:
            current_connections = set()
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    connection_id = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                    current_connections.add(connection_id)
                    
                    if connection_id not in self.network_connections:
                        # New network connection
                        try:
                            # Get process info for this connection
                            process_name = "Unknown"
                            if conn.pid:
                                try:
                                    process = psutil.Process(conn.pid)
                                    process_name = process.name()
                                except:
                                    pass
                            
                            activity = UserActivity(
                                user_id=current_user,
                                timestamp=datetime.now(),
                                activity_type="network_connection",
                                resource=f"{conn.raddr.ip}:{conn.raddr.port}",
                                ip_address=conn.laddr.ip,
                                user_agent=f"Process: {process_name}",
                                location=self.get_geolocation(conn.raddr.ip),
                                success=True,
                                session_id=str(uuid.uuid4())
                            )
                            
                            # Check for suspicious connections and set risk
                            initial_risk = 0.0
                            if self.is_suspicious_connection(conn):
                                initial_risk = 0.5  # Medium risk for suspicious connections
                            else:
                                initial_risk = 0.05  # Very low risk for normal connections
                            
                            activity.risk_score = initial_risk
                            
                            monitor_user_activity(activity)
                            self.network_events.append(activity)
                            
                        except Exception as e:
                            logger.error(f"Error monitoring connection: {e}")
            
            self.network_connections = current_connections
            
        except Exception as e:
            logger.error(f"Error in network monitoring: {e}")
    
    def is_suspicious_connection(self, connection):
        """Check if a network connection is suspicious"""
        # Check for connections to known suspicious ports
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
        if connection.raddr and connection.raddr.port in suspicious_ports:
            return True
        
        # Check for connections to localhost with high ports (potential backdoors)
        if connection.raddr and connection.raddr.ip == '127.0.0.1' and connection.raddr.port > 8000:
            return True
        
        return False
    
    def monitor_file_access(self):
        """Monitor file system access (optimized version)"""
        try:
            # Monitor only user directories to reduce performance impact
            sensitive_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop")
            ]
            
            for directory in sensitive_dirs:
                if os.path.exists(directory):
                    try:
                        # Only check a few recent files to avoid performance issues
                        files = []
                        for root, dirs, filenames in os.walk(directory):
                            for filename in filenames[:3]:  # Limit to 3 files per directory
                                files.append(os.path.join(root, filename))
                            break  # Only check first level
                        
                        for file_path in files:
                            try:
                                stat = os.stat(file_path)
                                modified_time = datetime.fromtimestamp(stat.st_mtime)
                                
                                # If file was modified in the last 2 minutes (increased threshold)
                                if (datetime.now() - modified_time).total_seconds() < 120:
                                    activity = UserActivity(
                                        user_id=current_user,
                                        timestamp=modified_time,
                                        activity_type="file_access",
                                        resource=os.path.basename(file_path),  # Use basename to avoid long paths
                                        ip_address="127.0.0.1",
                                        user_agent=f"File System Access",
                                        location="Local Network",
                                        success=True,
                                        session_id=str(uuid.uuid4())
                                    )
                                    
                                    # Check for suspicious file access and set risk
                                    initial_risk = 0.0
                                    if self.is_suspicious_file_access(file_path):
                                        initial_risk = 0.4  # Medium risk for suspicious file access
                                    else:
                                        initial_risk = 0.02  # Very low risk for normal file access
                                    
                                    activity.risk_score = initial_risk
                                    
                                    monitor_user_activity(activity)
                                    self.file_events.append(activity)
                                    
                            except (OSError, PermissionError):
                                continue
                    except (OSError, PermissionError):
                        continue
        except Exception as e:
            logger.error(f"Error in file monitoring: {e}")
    
    def is_suspicious_file_access(self, file_path):
        """Check if file access is suspicious"""
        suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr']
        suspicious_locations = ['\\temp\\', '\\tmp\\', '\\system32\\']
        
        file_path_lower = file_path.lower()
        
        # Check for executable files in temp directories
        if any(ext in file_path_lower for ext in suspicious_extensions):
            if any(loc in file_path_lower for loc in suspicious_locations):
                return True
        
        # Check for system file modifications
        if '\\system32\\' in file_path_lower and file_path_lower.endswith('.exe'):
            return True
        
        return False
    
    def monitor_system_events(self):
        """Monitor Windows system events (simplified)"""
        try:
            # Monitor user login events from Windows Event Log
            # This is a simplified version - in production, you'd want to use proper Windows API
            
            # Simulate login detection by checking for new user sessions
            current_time = datetime.now()
            
            # Check for system startup (simplified)
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            if (current_time - boot_time).total_seconds() < 300:  # Within 5 minutes of boot
                activity = UserActivity(
                    user_id=current_user,
                    timestamp=boot_time,
                    activity_type="system_boot",
                    resource="System",
                    ip_address=self.get_local_ip(),
                    user_agent="Windows System",
                    location=self.get_geolocation(self.get_local_ip()),
                    success=True,
                    session_id=str(uuid.uuid4())
                )
                
                monitor_user_activity(activity)
                self.login_events.append(activity)
        
        except Exception as e:
            logger.error(f"Error in system event monitoring: {e}")
    
    def monitor_user_behavior(self):
        """Monitor user behavior patterns"""
        try:
            # Monitor active window (requires additional libraries for full implementation)
            # For now, we'll track general system activity
            
            # CPU and memory usage patterns
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 80 or memory_percent > 90:
                activity = UserActivity(
                    user_id=current_user,
                    timestamp=datetime.now(),
                    activity_type="high_resource_usage",
                    resource=f"CPU: {cpu_percent}%, RAM: {memory_percent}%",
                    ip_address=self.get_local_ip(),
                    user_agent="System Monitor",
                    location=self.get_geolocation(self.get_local_ip()),
                    success=True,
                    risk_score=0.5 if cpu_percent > 90 else 0.2,
                    session_id=str(uuid.uuid4())
                )
                
                monitor_user_activity(activity)
        
        except Exception as e:
            logger.error(f"Error in user behavior monitoring: {e}")
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        self.running = True
        logger.info("Starting real-time system monitoring...")
        
        # Create monitoring threads
        monitoring_threads = [
            threading.Thread(target=self._process_monitor_loop, daemon=True),
            threading.Thread(target=self._network_monitor_loop, daemon=True),
            threading.Thread(target=self._file_monitor_loop, daemon=True),
            threading.Thread(target=self._system_monitor_loop, daemon=True),
            threading.Thread(target=self._behavior_monitor_loop, daemon=True)
        ]
        
        for thread in monitoring_threads:
            thread.start()
        
        logger.info("Real-time monitoring started successfully")
    
    def _process_monitor_loop(self):
        """Process monitoring loop"""
        while self.running:
            try:
                self.monitor_processes()
                time.sleep(10)  # Increased from 5 to 10 seconds
            except Exception as e:
                logger.error(f"Process monitor loop error: {e}")
                time.sleep(15)
    
    def _network_monitor_loop(self):
        """Network monitoring loop"""
        while self.running:
            try:
                self.monitor_network_connections()
                time.sleep(20)  # Increased from 10 to 20 seconds
            except Exception as e:
                logger.error(f"Network monitor loop error: {e}")
                time.sleep(30)
    
    def _file_monitor_loop(self):
        """File monitoring loop"""
        while self.running:
            try:
                self.monitor_file_access()
                time.sleep(60)  # Increased from 30 to 60 seconds
            except Exception as e:
                logger.error(f"File monitor loop error: {e}")
                time.sleep(60)
    
    def _system_monitor_loop(self):
        """System monitoring loop"""
        while self.running:
            try:
                self.monitor_system_events()
                time.sleep(120)  # Increased from 60 to 120 seconds
            except Exception as e:
                logger.error(f"System monitor loop error: {e}")
                time.sleep(120)
    
    def _behavior_monitor_loop(self):
        """Behavior monitoring loop"""
        while self.running:
            try:
                self.monitor_user_behavior()
                time.sleep(30)  # Increased from 15 to 30 seconds
            except Exception as e:
                logger.error(f"Behavior monitor loop error: {e}")
                time.sleep(30)
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
        logger.info("Real-time monitoring stopped")

@dataclass
class UserActivity:
    user_id: str
    timestamp: datetime
    activity_type: str
    resource: str
    ip_address: str
    user_agent: str
    location: str
    success: bool
    risk_score: float = 0.0
    session_id: str = ""

@dataclass
class UserProfile:
    user_id: str
    normal_login_hours: List[int]
    normal_locations: List[str]
    normal_resources: List[str]
    avg_session_duration: float
    typical_actions_per_session: int
    creation_date: datetime
    last_updated: datetime

class UBAAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.15, random_state=42)
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=5)
        self.is_trained = False
        self.baseline_patterns = {}
        self.user_profiles = {}
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'session_duration', 
            'actions_per_session', 'unique_resources', 'failed_attempts',
            'location_entropy', 'time_since_last_login'
        ]
        
    def extract_features(self, activities: List[UserActivity]) -> np.ndarray:
        """Extract features from user activities for anomaly detection"""
        features = []
        
        for activity in activities:
            # Time-based features
            hour_of_day = activity.timestamp.hour
            day_of_week = activity.timestamp.weekday()
            
            # Session-based features (simplified)
            session_duration = 60  # Default session duration in minutes
            actions_per_session = 1
            unique_resources = 1
            failed_attempts = 0 if activity.success else 1
            
            # Location entropy (simplified)
            location_entropy = hash(activity.location) % 100 / 100.0
            
            # Time since last login (simplified)
            time_since_last_login = 0
            
            feature_vector = [
                hour_of_day, day_of_week, session_duration,
                actions_per_session, unique_resources, failed_attempts,
                location_entropy, time_since_last_login
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def calculate_rule_based_risk(self, activity: UserActivity) -> float:
        """Calculate risk score using rule-based approach"""
        risk_score = 0.0
        
        # Time-based risk (unusual hours)
        hour = activity.timestamp.hour
        if hour < 6 or hour > 22:  # Late night/early morning
            risk_score += 0.3
        
        # Activity type risk
        high_risk_activities = ['command_execution', 'process_start']
        medium_risk_activities = ['file_access', 'network_connection']
        
        if activity.activity_type in high_risk_activities:
            risk_score += 0.2
        elif activity.activity_type in medium_risk_activities:
            risk_score += 0.1
        
        # Resource-based risk
        suspicious_processes = ['cmd.exe', 'powershell.exe', 'netsh.exe', 'sc.exe']
        if any(proc in activity.resource.lower() for proc in suspicious_processes):
            risk_score += 0.4
        
        # Failure risk
        if not activity.success:
            risk_score += 0.3
        
        # Location risk
        if activity.location == "External Network":
            risk_score += 0.2
        
        # Normalize to 0-1 range
        return min(1.0, risk_score)
    
    def calculate_statistical_risk(self, activity: UserActivity) -> float:
        """Calculate risk based on statistical deviation from normal patterns"""
        user_id = activity.user_id
        
        if user_id not in self.user_profiles:
            return 0.1  # Low risk for new users
        
        profile = self.user_profiles[user_id]
        risk_score = 0.0
        
        # Check time pattern deviation
        current_hour = activity.timestamp.hour
        if profile.get('normal_hours'):
            if current_hour not in profile['normal_hours']:
                risk_score += 0.2
        
        # Check location deviation
        if profile.get('normal_locations'):
            if activity.location not in profile['normal_locations']:
                risk_score += 0.3
        
        # Check activity frequency
        if profile.get('activity_frequency'):
            expected_freq = profile['activity_frequency'].get(activity.activity_type, 0)
            if expected_freq < 0.1:  # Rare activity type for this user
                risk_score += 0.2
        
        return min(1.0, risk_score)
    
    def update_user_profile(self, activity: UserActivity):
        """Update user behavior profile"""
        user_id = activity.user_id
        
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'normal_hours': set(),
                'normal_locations': set(),
                'activity_frequency': {},
                'total_activities': 0
            }
        
        profile = self.user_profiles[user_id]
        profile['normal_hours'].add(activity.timestamp.hour)
        profile['normal_locations'].add(activity.location)
        
        # Update activity frequency
        activity_type = activity.activity_type
        if activity_type not in profile['activity_frequency']:
            profile['activity_frequency'][activity_type] = 0
        profile['activity_frequency'][activity_type] += 1
        profile['total_activities'] += 1
        
        # Normalize frequencies
        for act_type in profile['activity_frequency']:
            profile['activity_frequency'][act_type] = (
                profile['activity_frequency'][act_type] / profile['total_activities']
            )
    
    def train(self, activities: List[UserActivity]):
        """Train the anomaly detection model with better data diversity"""
        if len(activities) < 10:
            logger.warning("Insufficient data for training - using rule-based approach")
            self.is_trained = False
            return
        
        # Build user profiles
        for activity in activities:
            self.update_user_profile(activity)
        
        # Only train ML model if we have sufficient diverse data
        if len(activities) > 50:
            try:
                features = self.extract_features(activities)
                
                # Add some noise to create more realistic training data
                noise = np.random.normal(0, 0.1, features.shape)
                features_with_noise = features + noise
                
                # Normalize features
                features_scaled = self.scaler.fit_transform(features_with_noise)
                
                # Apply PCA for dimensionality reduction
                features_pca = self.pca.fit_transform(features_scaled)
                
                # Train isolation forest
                self.isolation_forest.fit(features_pca)
                self.is_trained = True
                
                logger.info(f"ML model trained on {len(activities)} activities")
            except Exception as e:
                logger.error(f"Error training ML model: {e}")
                self.is_trained = False
        else:
            self.is_trained = False
            logger.info("Using rule-based risk assessment (insufficient data for ML)")
    
    def predict_anomaly(self, activity: UserActivity) -> Tuple[bool, float]:
        """Predict if an activity is anomalous using hybrid approach"""
        # Always update user profile
        self.update_user_profile(activity)
        
        # Calculate rule-based risk
        rule_risk = self.calculate_rule_based_risk(activity)
        
        # Calculate statistical risk
        stat_risk = self.calculate_statistical_risk(activity)
        
        # If ML model is trained, use it as well
        ml_risk = 0.0
        if self.is_trained:
            try:
                features = self.extract_features([activity])
                features_scaled = self.scaler.transform(features)
                features_pca = self.pca.transform(features_scaled)
                
                # Get anomaly score
                anomaly_score = self.isolation_forest.decision_function(features_pca)[0]
                is_anomaly = self.isolation_forest.predict(features_pca)[0] == -1
                
                # Convert to risk score (0-1 scale)
                ml_risk = max(0, min(1, (0.5 - anomaly_score) / 0.5)) if is_anomaly else 0.1
            except Exception as e:
                logger.error(f"Error in ML prediction: {e}")
                ml_risk = 0.0
        
        # Combine risk scores with weights
        if self.is_trained:
            # Use weighted combination when ML is available
            final_risk = (0.4 * rule_risk) + (0.3 * stat_risk) + (0.3 * ml_risk)
        else:
            # Use rule-based and statistical only
            final_risk = (0.6 * rule_risk) + (0.4 * stat_risk)
        
        # Apply some randomness to make it more realistic
        final_risk *= np.random.uniform(0.8, 1.2)
        final_risk = max(0.01, min(0.99, final_risk))  # Keep in reasonable range
        
        is_anomaly = final_risk > 0.7
        
        return is_anomaly, final_risk

class DatabaseManager:
    def __init__(self, db_path="uba_platform.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_db_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Fix datetime deprecation warning
        sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
        sqlite3.register_converter("timestamp", lambda dt: datetime.fromisoformat(dt.decode()))
        try:
            yield conn
        finally:
            conn.close()
    
    def init_database(self):
        with self.get_db_connection() as conn:
            # Configure SQLite for better performance
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE,
                    username TEXT,
                    email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    timestamp TEXT,
                    activity_type TEXT,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    location TEXT,
                    success BOOLEAN,
                    risk_score REAL,
                    session_id TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                );
                
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    alert_type TEXT,
                    description TEXT,
                    severity TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_activities_user_timestamp 
                ON activities(user_id, timestamp);
                
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp);
            """)
            conn.commit()
    
    def add_user(self, user_id: str, username: str, email: str):
        with self.get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (user_id, username, email) VALUES (?, ?, ?)",
                (user_id, username, email)
            )
            conn.commit()
    
    def log_activity(self, activity: UserActivity):
        with self.get_db_connection() as conn:
            # Use batch inserts and reduce transaction frequency
            conn.execute("PRAGMA journal_mode=WAL")  # Use WAL mode to reduce journal file creation
            conn.execute("""
                INSERT INTO activities 
                (user_id, timestamp, activity_type, resource, ip_address, 
                 user_agent, location, success, risk_score, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                activity.user_id, activity.timestamp.isoformat(), activity.activity_type,
                activity.resource, activity.ip_address, activity.user_agent,
                activity.location, activity.success, activity.risk_score,
                activity.session_id
            ))
            conn.commit()
    
    def get_user_activities(self, user_id: str, limit: int = 1000) -> List[UserActivity]:
        with self.get_db_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM activities 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (user_id, limit))
            
            activities = []
            for row in cursor.fetchall():
                activity = UserActivity(
                    user_id=row['user_id'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    activity_type=row['activity_type'],
                    resource=row['resource'],
                    ip_address=row['ip_address'],
                    user_agent=row['user_agent'],
                    location=row['location'],
                    success=bool(row['success']),
                    risk_score=row['risk_score'],
                    session_id=row['session_id']
                )
                activities.append(activity)
            
            return activities
    
    def create_alert(self, user_id: str, alert_type: str, description: str, severity: str):
        with self.get_db_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (user_id, alert_type, description, severity)
                VALUES (?, ?, ?, ?)
            """, (user_id, alert_type, description, severity))
            conn.commit()
    
    def get_recent_alerts(self, limit: int = 100) -> List[dict]:
        with self.get_db_connection() as conn:
            cursor = conn.execute("""
                SELECT a.*, u.username 
                FROM alerts a
                JOIN users u ON a.user_id = u.user_id
                WHERE a.resolved = FALSE
                ORDER BY a.timestamp DESC
                LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]

# Initialize components
db_manager = DatabaseManager()
uba_analyzer = UBAAnalyzer()

# Create system monitor instance
system_monitor = RealTimeSystemMonitor()

# Add current user to database
current_user_info = system_monitor.get_current_user_info()
db_manager.add_user(
    current_user_info.get('username', 'unknown'), 
    current_user_info.get('username', 'unknown'), 
    f"{current_user_info.get('username', 'unknown')}@{current_user_info.get('machine', 'localhost')}"
)

def generate_initial_sample_activities():
    """Generate diverse sample activities for realistic model training"""
    activities = []
    
    # Generate realistic baseline activities with patterns
    activity_types = ["login", "file_access", "process_start", "network_connection", "logout"]
    normal_resources = ["notepad.exe", "chrome.exe", "explorer.exe", "outlook.exe", "calculator.exe"]
    suspicious_resources = ["cmd.exe", "powershell.exe", "netsh.exe", "systeminfo", "tasklist"]
    
    # Generate normal working hour activities (80% of data)
    for i in range(60):
        # Normal business hours (9 AM to 6 PM)
        hour = np.random.choice([9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
        timestamp = datetime.now() - timedelta(
            days=np.random.randint(0, 7),
            hours=hour,
            minutes=np.random.randint(0, 60)
        )
        
        activity = UserActivity(
            user_id=current_user,
            timestamp=timestamp,
            activity_type=np.random.choice(activity_types),
            resource=np.random.choice(normal_resources),
            ip_address="127.0.0.1",
            user_agent="Normal Activity",
            location="Local Network",
            success=True,  # Normal activities are usually successful
            session_id=str(uuid.uuid4())
        )
        activities.append(activity)
    
    # Generate some off-hours activities (15% of data)
    for i in range(15):
        # Off hours
        hour = np.random.choice([22, 23, 0, 1, 2, 6, 7, 8])
        timestamp = datetime.now() - timedelta(
            days=np.random.randint(0, 7),
            hours=hour,
            minutes=np.random.randint(0, 60)
        )
        
        activity = UserActivity(
            user_id=current_user,
            timestamp=timestamp,
            activity_type=np.random.choice(["login", "file_access"]),
            resource=np.random.choice(normal_resources),
            ip_address="127.0.0.1",
            user_agent="Off Hours Activity",
            location="Local Network",
            success=True,
            session_id=str(uuid.uuid4())
        )
        activities.append(activity)
    
    # Generate some suspicious activities (5% of data)
    for i in range(5):
        hour = np.random.choice([2, 3, 4])  # Very unusual hours
        timestamp = datetime.now() - timedelta(
            days=np.random.randint(0, 3),
            hours=hour,
            minutes=np.random.randint(0, 60)
        )
        
        activity = UserActivity(
            user_id=current_user,
            timestamp=timestamp,
            activity_type="command_execution",
            resource=np.random.choice(suspicious_resources),
            ip_address="127.0.0.1",
            user_agent="Suspicious Activity",
            location="Local Network",
            success=np.random.choice([True, False]),  # Some failures
            session_id=str(uuid.uuid4())
        )
        activities.append(activity)
    
    # Batch insert all activities at once
    with db_manager.get_db_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        for activity in activities:
            conn.execute("""
                INSERT INTO activities 
                (user_id, timestamp, activity_type, resource, ip_address, 
                 user_agent, location, success, risk_score, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                activity.user_id, activity.timestamp.isoformat(), activity.activity_type,
                activity.resource, activity.ip_address, activity.user_agent,
                activity.location, activity.success, 0.0,  # Initialize with 0 risk
                activity.session_id
            ))
        conn.commit()
    
    logger.info(f"Generated {len(activities)} diverse training activities")
    return activities

# Generate initial sample data and train model
try:
    logger.info("Generating initial sample data and training model...")
    sample_activities = generate_initial_sample_activities()
    uba_analyzer.train(sample_activities)
    logger.info("Initial model training completed successfully")
except Exception as e:
    logger.error(f"Error during initialization: {e}")
    # Continue with empty data if sample generation fails

def monitor_user_activity(activity: UserActivity):
    """Monitor and analyze user activity in real-time with improved risk assessment"""
    global activity_buffer
    
    # Add to buffer
    activity_buffer.append(activity)
    
    # Analyze for anomalies using the improved ML model
    is_anomaly, risk_score = uba_analyzer.predict_anomaly(activity)
    
    # Override the risk score with the calculated one
    activity.risk_score = risk_score
    
    # Log to database
    db_manager.log_activity(activity)
    
    # Create alert for high-risk activities (adjusted threshold)
    if risk_score > 0.6:  # Lowered from 0.7 to catch more varied risks
        alert_description = f"Elevated risk {activity.activity_type} activity detected for user {activity.user_id} (Risk: {risk_score:.1%})"
        severity = "HIGH" if risk_score > 0.8 else "MEDIUM"
        db_manager.create_alert(activity.user_id, "anomaly_detection", alert_description, severity)
        
        # Emit real-time alert
        socketio.emit('new_alert', {
            'user_id': activity.user_id,
            'activity_type': activity.activity_type,
            'risk_score': risk_score,
            'timestamp': activity.timestamp.isoformat(),
            'description': alert_description
        })
    
    # Emit real-time activity update
    socketio.emit('new_activity', {
        'user_id': activity.user_id,
        'activity_type': activity.activity_type,
        'resource': activity.resource,
        'risk_score': risk_score,
        'timestamp': activity.timestamp.isoformat(),
        'success': activity.success
    })

# Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/activities')
def get_activities():
    user_id = request.args.get('user_id')
    limit = int(request.args.get('limit', 100))
    
    if user_id:
        activities = db_manager.get_user_activities(user_id, limit)
    else:
        # Get activities for current user
        activities = db_manager.get_user_activities(current_user, limit)
    
    # Sort by timestamp
    activities.sort(key=lambda x: x.timestamp, reverse=True)
    
    return jsonify([{
        'user_id': a.user_id,
        'timestamp': a.timestamp.isoformat(),
        'activity_type': a.activity_type,
        'resource': a.resource,
        'risk_score': a.risk_score,
        'success': a.success,
        'location': a.location,
        'ip_address': a.ip_address
    } for a in activities[:limit]])

@app.route('/api/alerts')
def get_alerts():
    alerts = db_manager.get_recent_alerts()
    return jsonify(alerts)

@app.route('/api/users')
def get_users():
    with db_manager.get_db_connection() as conn:
        cursor = conn.execute("SELECT user_id, username FROM users")
        users = [dict(row) for row in cursor.fetchall()]
    return jsonify(users)

@app.route('/api/system_info')
def get_system_info():
    """Get current system information"""
    try:
        info = system_monitor.get_current_user_info()
        info.update({
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent,
            'active_processes': len(list(psutil.process_iter())),
            'network_connections': len(psutil.net_connections()),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
        })
        return jsonify(info)
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({'error': 'Unable to get system information'}), 500

@app.route('/api/simulate_activity', methods=['POST'])
def simulate_activity():
    """Simulate user activity for testing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        activity = UserActivity(
            user_id=data.get('user_id', 'user1'),
            timestamp=datetime.now(),
            activity_type=data.get('activity_type', 'login'),
            resource=data.get('resource', 'server1'),
            ip_address=data.get('ip_address', '192.168.1.100'),
            user_agent=data.get('user_agent', 'Mozilla/5.0'),
            location=data.get('location', 'New York'),
            success=data.get('success', True),
            session_id=str(uuid.uuid4())
        )
        
        monitor_user_activity(activity)
        
        return jsonify({
            'status': 'success',
            'risk_score': activity.risk_score,
            'message': 'Activity logged successfully'
        })
    except Exception as e:
        logger.error(f"Error in simulate_activity: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user_profile/<user_id>')
def get_user_profile(user_id):
    activities = db_manager.get_user_activities(user_id, 1000)
    
    if not activities:
        return jsonify({'error': 'User not found'}), 404
    
    # Calculate profile statistics
    login_hours = [a.timestamp.hour for a in activities if a.activity_type == 'login']
    locations = [a.location for a in activities]
    resources = [a.resource for a in activities]
    
    profile = {
        'user_id': user_id,
        'total_activities': len(activities),
        'success_rate': sum(1 for a in activities if a.success) / len(activities) if activities else 0,
        'avg_risk_score': sum(a.risk_score for a in activities) / len(activities) if activities else 0,
        'common_login_hours': list(set(login_hours)),
        'common_locations': list(set(locations)),
        'common_resources': list(set(resources)),
        'recent_activities': len([a for a in activities if a.timestamp > datetime.now() - timedelta(days=7)])
    }
    
    return jsonify(profile)

# Start real-time monitoring
def start_real_time_monitoring():
    """Start real-time system monitoring"""
    try:
        system_monitor.start_monitoring()
        logger.info("Real-time monitoring started successfully")
    except Exception as e:
        logger.error(f"Error starting real-time monitoring: {e}")

if __name__ == '__main__':
    try:
        # Start real-time monitoring
        start_real_time_monitoring()
        
        # Start the Flask-SocketIO server
        logger.info("Starting UBA Platform server on http://localhost:5000")
        logger.info(f"Monitoring user: {current_user} on machine: {current_machine}")
        socketio.run(app, debug=False, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        if system_monitor:
            system_monitor.stop_monitoring()
    except Exception as e:
        logger.error(f"Server error: {e}")
        if system_monitor:
            system_monitor.stop_monitoring()
        raise