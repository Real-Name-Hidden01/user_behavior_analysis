# UBA Platform - Real-Time User Behavior Analytics

This is a real-time User Behavior Analytics (UBA) platform that monitors actual user activities on your Windows system and detects anomalous behavior using machine learning.

## Features

- **Real-Time Monitoring**: Monitors actual system activities including:
  - Process creation and termination
  - Network connections
  - File system access
  - System resource usage
  - User login/logout events

- **Anomaly Detection**: Uses Isolation Forest machine learning algorithm to detect suspicious activities

- **Real-Time Dashboard**: Web-based dashboard with:
  - Live activity feed
  - Risk score visualization
  - System performance metrics
  - Alert management
  - User behavior analytics

- **Activity Simulation**: Test the system with simulated activities

## Installation

1. **Install Python Dependencies**:
   ```
   pip install -r requirements.txt
   ```

2. **Run the Application**:
   ```
   python app.py
   ```
   
   Or use the batch file:
   ```
   run.bat
   ```

## Usage

1. **Start the Application**: Run `python app.py` or `run.bat`

2. **Access the Dashboard**: Open your browser and go to `http://localhost:5000`

3. **Monitor Activities**: The dashboard will show real-time activities from your system

4. **Generate Test Activities**: Run `python test_activities.py` to generate test activities for demonstration

## Dashboard Sections

### 1. Dashboard
- Overview of system activities
- Risk score statistics
- Real-time charts
- Recent alerts

### 2. Activities
- Detailed list of all monitored activities
- Filter by user
- Real-time updates

### 3. Alerts
- Security alerts for high-risk activities
- Alert management

### 4. Users
- User profiles and statistics
- Behavior analysis

### 5. Analytics
- Advanced analytics and patterns
- Various charts and visualizations

### 6. Simulate
- Generate test activities
- Test the anomaly detection system

## Monitored Activities

The platform monitors the following types of activities:

- **Process Activities**: Starting/stopping applications and processes
- **Network Activities**: Network connections and communications
- **File Activities**: File access and modifications
- **System Activities**: System boot, resource usage
- **User Activities**: Login/logout events

## Risk Assessment

Each activity is assigned a risk score (0-100%) based on:
- Time patterns (unusual hours)
- Location anomalies
- Process behavior
- Network connections
- File access patterns
- Resource usage

## Security Features

- **Anomaly Detection**: Machine learning-based detection of unusual behavior
- **Real-Time Alerts**: Immediate notifications for high-risk activities
- **Activity Logging**: Comprehensive logging of all activities
- **Risk Scoring**: Automated risk assessment for each activity

## Technical Details

- **Backend**: Flask with Socket.IO for real-time communication
- **Frontend**: Bootstrap with Chart.js for visualization
- **Database**: SQLite for activity storage
- **Monitoring**: psutil for system monitoring
- **ML**: scikit-learn for anomaly detection

## Requirements

- Python 3.7+
- Windows operating system
- Administrator privileges (recommended for full monitoring capabilities)

## Demo Instructions

1. Start the application with `python app.py`
2. Open the dashboard at `http://localhost:5000`
3. Run `python test_activities.py` to generate demo activities
4. Watch the real-time updates in the dashboard
5. Check the alerts for detected anomalies

## Notes

- The application monitors real system activities
- High-risk activities will trigger alerts
- The machine learning model learns from your usage patterns
- All data is stored locally in SQLite database

## Troubleshooting

- Ensure Python and pip are installed
- Install all requirements: `pip install -r requirements.txt`
- Run as administrator for full system monitoring
- Check firewall settings if dashboard doesn't load
- View console logs for error messages

## Security Notice

This application monitors system activities for security purposes. It does not transmit data outside your local system. All monitoring data is stored locally in the SQLite database.
