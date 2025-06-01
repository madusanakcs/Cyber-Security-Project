from collections import defaultdict
from datetime import datetime
import statistics
from device_activity import DeviceActivity
from collections import defaultdict, deque


'''
Event details used

'register'
New user is registered

'login_attempt'
User logs in
In context, it has 'status': 'success' or 'failure'

'''

class AnomalyDetector(object):
    # Flag indexes
    RATE_FLAG = 0
    VALUE_FLAG = 1
    ROLE_FLAG = 2
    UNEXPECTED_FLAG = 3
    ACTIVITY_FLAG = 4
    
    # List of critical events
    CRITICAL_EVENTS = ['reboot', 'update_firmware', 'disable_device', 'disable_alarm']
    # List of device/sensor reporting events
    REPORTING_EVENT = ['device_heartbeat', 'sensor_report', 'power_report', 'data_sync']

    ROLE_BASED_THRESHOLDS = {
        'login_attempt_failure': {
            'USER': (5, 60),
            'ADMIN': (3, 60),
            'MANAGER': (7, 60)
        },
        'toggle_device': {
            'USER': (10, 30),
            'ADMIN': (20, 30),
            'MANAGER': (15, 30)
        },
        'password_change': {
            'USER': (2, 1800),  # 2 in 30 minutes
            'ADMIN': (3, 1800),
            'MANAGER': (3, 1800)
        },
        'device_registration': {
            'USER': (5, 3600),  # 5 in 1 hour
            'ADMIN': (10, 3600),
            'MANAGER': (7, 3600)
        }
    }



    # Thresholds
    NEW_SOURCE_RESET_THRES = 2 * 24 * 60 * 60
    NEW_SOURCE_CRITICAL_THRES = 2 * 60 * 60

    INACTIVITY_CHECK_PERIOD = 60

    def __init__(self):

        # List of registered users
        self.regUsers = {}
        # Source IDs of different users
        self.userSourceMap = defaultdict(list)
        # Number of times a user logged in from a new source
        self.userNewSourceCount = {}

        # Used to check device activity intervals
        self.deviceActivityIntervals = defaultdict(DeviceActivity)
        # Time of last inactivity check
        self.lastInactivityCheck = 0
        # Store event timestamps for each user and source
        self.eventTimestamps = defaultdict(lambda: defaultdict(deque))


        self.devicePowerHistory = defaultdict(list)  # device_id -> list of power readings
        self.deviceTemperatureHistory = defaultdict(list)

    def instrument(self, eventName: str, userRole: str, userId: str, sourceId: str, timestamp: float, context: dict):
        # Assume that details related to a event is in the context.
        # Eg. eventName = "toggle_device", context = {'device_name': 'light'}
        flag = [False] * 5

        # Implement different types of analytic functions

        #1 Rate checks
        flag[0] = self.checkRateAnomaly(eventName, userId, sourceId, timestamp, context, userRole)

        #2 Value checks
        flag[1] = self.checkValueAnomaly(eventName, userId, timestamp, context) 

        #3 Role aware filtering
        flag[2] = self.checkRoleAwareFiltering(eventName, userRole, userId, sourceId, timestamp, context)

        #4 Unexpected user or source for the command
        flag[3] = self.checkUnexpectedUser(eventName, userRole, userId, sourceId, timestamp, context)

        #5 Anomaly in device activity
        flag[4] = self.checkActivityIntervals(eventName, timestamp, context)

        return flag
    
    def logAnomaly(self, timestamp, type, message):
        # Use this function for logging instead of print
        print(f"[{datetime.fromtimestamp(timestamp)}] {type}: {message}")

    
    ##  Rate Check
    def checkRateAnomaly(self, eventName, userId, sourceId, timestamp, context, userRole):
        flagged = False
        
        # Handle failed login attempts separately
        if eventName == 'login_attempt' and context.get('status') == 'failure':
            event_key = 'login_attempt_failure'
        else:
            event_key = eventName

        # Check if the event is one with rate-limiting thresholds
        if event_key in self.ROLE_BASED_THRESHOLDS:
            if userRole not in self.ROLE_BASED_THRESHOLDS[event_key]:
                return False  # No rule defined for this role
            
            max_count, interval = self.ROLE_BASED_THRESHOLDS[event_key][userRole]
            
            # Get the queue of event timestamps for this user-event
            timestamps = self.eventTimestamps[userId][event_key]
            
            # Remove timestamps outside the interval
            while timestamps and timestamp - timestamps[0] > interval:
                timestamps.popleft()
            
            # Add current timestamp
            timestamps.append(timestamp)

            # Check if the rate exceeded
            if len(timestamps) > max_count:
                self.logAnomaly(timestamp, "ALERT", 
                            f"Too many {event_key} events by {userId} from {sourceId} "
                            f"({len(timestamps)} in {interval} seconds)")
                flagged = True

        return flagged


    ##  Unexpected User or Source

    def checkUnexpectedUser(self, eventName, userRole, userId, sourceId, timestamp, context):
        flag = False

        # if new user add them to the user list
        if eventName == 'register':
            self.regUsers[userId] = userRole
            self.userSourceMap[userId].append(sourceId)
            self.userNewSourceCount[userId] = {'count': 0, 'last': 0}

        # if user login, check whether it was from a new source
        if eventName == 'login_attempt' and context['status'] == 'success':
            if sourceId not in self.userSourceMap[userId]:
                self.logAnomaly(timestamp, "WARNING", f"User {userId} logged in from new source {sourceId}")
                self.userSourceMap[userId].append(sourceId)

                # Update new source count and reset it if more than 2 days have passed
                newSourceCount = self.userNewSourceCount[userId]
                if timestamp - newSourceCount['last'] > AnomalyDetector.NEW_SOURCE_RESET_THRES:   # 2 days since last new source
                    newSourceCount['count'] = 1
                else:
                    newSourceCount['count'] += 1
                newSourceCount['last'] = timestamp

                # if 3 or more new login sources within 2 days, alert
                if newSourceCount['count'] >= 3:
                    self.logAnomaly(timestamp, "ALERT", f"User {userId} logged in from {newSourceCount['count']} new sources within the last 2 days")
                    flag = True
                self.userNewSourceCount[userId] = newSourceCount

        # Flag if a critical function is triggered by a user who recently logged in from a new source
        if eventName in AnomalyDetector.CRITICAL_EVENTS:
            if timestamp - self.userNewSourceCount[userId]['last'] <= AnomalyDetector.NEW_SOURCE_CRITICAL_THRES:
                self.logAnomaly(timestamp, "ALERT", f"Event {eventName} triggered by user {userId} logged in from new source {sourceId}")
                flag = True

        return flag
    

    # Value Anomaly
    def checkValueAnomaly(self, eventName, userId, timestamp, context):
        """
        Detect anomalies in power and temperature readings.

        Power reading checks:
        - Negative or zero values
        - >150% of average (spike)
        - <50% of average (drop)
        - Stuck readings

        Temperature reading checks:
        - Out-of-range (< -40 or > 100 C)
        - >120% of average (spike)
        - <80% of average (drop)
        - Stuck readings
        """
        flag = False

        device_id = context.get('device_id')
        value = context.get('value')

        if value is None or device_id is None:
            return False

        if eventName == 'power_reading':
            history = self.devicePowerHistory[device_id]

            if value <= 0:
                self.logAnomaly(timestamp, "ALERT", f"Negative or zero power value {value} reported by device {device_id}")
                return True

            if len(history) >= 5:
                avg = statistics.mean(history)
                if value > 1.5 * avg:
                    self.logAnomaly(timestamp, "ALERT", f"Power spike: {value}W > 150% of avg {avg:.2f}W from device {device_id}")
                    flag = True
                if value < 0.5 * avg:
                    self.logAnomaly(timestamp, "ALERT", f"Power drop: {value}W < 50% of avg {avg:.2f}W from device {device_id}")
                    flag = True
                if len(set(history[-5:])) == 1 and value == history[-1]:
                    self.logAnomaly(timestamp, "ALERT", f"Stuck power sensor: same value {value}W repeatedly from device {device_id}")
                    flag = True

            history.append(value)
            if len(history) > 100:
                history.pop(0)

        elif eventName == 'temperature_reading':
            history = self.deviceTemperatureHistory[device_id]

            if value < -40 or value > 100:
                self.logAnomaly(timestamp, "ALERT", f"Out-of-range temperature: {value}°C from device {device_id}")
                return True

            if len(history) >= 5:
                avg = statistics.mean(history)
                if value > 1.2 * avg:
                    self.logAnomaly(timestamp, "ALERT", f"Temperature spike: {value}°C > 120% of avg {avg:.2f}°C from device {device_id}")
                    flag = True
                if value < 0.8 * avg:
                    self.logAnomaly(timestamp, "ALERT", f"Temperature drop: {value}°C < 80% of avg {avg:.2f}°C from device {device_id}")
                    flag = True
                if len(set(history[-5:])) == 1 and value == history[-1]:
                    self.logAnomaly(timestamp, "ALERT", f"Stuck temperature sensor: value {value}°C repeated from device {device_id}")
                    flag = True

            history.append(value)
            if len(history) > 100:
                history.pop(0)

        return flag
    
    

    def checkActivityIntervals(self, eventName, timestamp, context):
        flag = False

        # periodically check for inactivity of all events
        if timestamp - self.lastInactivityCheck >= AnomalyDetector.INACTIVITY_CHECK_PERIOD:
            for eventId, activityObj in self.deviceActivityIntervals.items():
                # Check next inactivity check time to avoid unnecessary logs
                if timestamp < activityObj.nextInactiveCheck: continue

                # Check if inactive
                if activityObj.checkGreaterThanAvg(timestamp):
                    interval = activityObj.getCurInterval(timestamp)
                    self.logAnomaly(timestamp, "ALERT", f"Inactivity detected for {eventId}: typically reports every {activityObj.avgInterval} s, inactive for {interval} s")
                    activityObj.nextInactiveCheck = timestamp + activityObj.avgInterval
                    flag = True

            self.lastInactivityCheck = timestamp


        # If the event is a device/sensor reporting event, check whether the reporting intervals are normal
        if eventName in AnomalyDetector.REPORTING_EVENT:
            eventId = eventName + "_" + context['device_id']
            activityObj = self.deviceActivityIntervals[eventId]

            # If the event is an update or reset of a device, reset the activity data
            if context.get('status') in ['update', 'reset']:
                activityObj.resetAvg()

            # Check if the rate suddenly became higher
            if activityObj.checkLessThanAvg(timestamp):
                interval = activityObj.getCurInterval(timestamp)
                activityObj.markAnomaly()
                if activityObj.anomalies >= DeviceActivity.ANOMALY_LIMIT:
                    self.logAnomaly(timestamp, "ALERT", f"Sudden increase of reporting rate for {eventId}: {activityObj.avgInterval} s to {interval} s")
                    flag = True

            # Check if the rate suddenly became lower
            elif activityObj.checkGreaterThanAvg(timestamp):
                interval = activityObj.getCurInterval(timestamp)
                activityObj.markAnomaly()
                if activityObj.anomalies >= DeviceActivity.ANOMALY_LIMIT:
                    self.logAnomaly(timestamp, "ALERT", f"Decrease of reporting rate for {eventId}: {activityObj.avgInterval} s to {interval} s")
                    flag = True

            # If no anomaly
            else: 
                if activityObj.anomalies > 0:
                    # Previously there was an anomaly but now it is back to normal
                    activityObj.anomalies = 0
                # Update the average
                activityObj.updateAvgInterval(timestamp)

            # Update prevTs
            activityObj.updatePrevTs(timestamp)

        return flag
    
    def checkRoleAwareFiltering(self, eventName, userRole, userId, sourceId, timestamp, context):
        flag = False
        hour = datetime.fromtimestamp(timestamp).hour
        
        # if userId not in self.regUsers:  
        #     self.logAnomaly(timestamp, "ALERT", f"Unregistered user {userId}!")
        #     return True
                    
        if eventName == 'login_attempt' and context.get('status') == 'success':
            if userRole == 'USER':
                self.logAnomaly(timestamp, "INFO", f"User {userId} with role {userRole} logged in")
                return False
                
            elif 8 <= hour < 18 and userRole in ['ADMIN', 'MANAGER'] :
                self.logAnomaly(timestamp, "INFO", f"User {userId} with role {userRole} logged in during business hours")
                return False  # business hours: no flag
            
            else:
                # After hours: flag new source logins by ADMIN, MANAGER
                if sourceId not in self.userSourceMap[userId]:
                    self.logAnomaly(timestamp, "ALERT", f"After-hours login by ADMIN {userId} from new source {sourceId}")
                    return True
                else:
                    self.logAnomaly(timestamp, "INFO", f"After-hours login by ADMIN {userId} from known source {sourceId}")
                    return False

        # Rule: Only MANAGERs can trigger 'update_firmware'
        if eventName == 'update_firmware' and userRole == 'MANAGER':
            self.logAnomaly(timestamp, "INFO", f"User {userId} with role {userRole} updated firmware")
            return False
        elif eventName == 'update_firmware' and userRole != 'MANAGER':
            self.logAnomaly(timestamp, "ALERT", f"User {userId} with role {userRole} tried to update firmware")
            return True
        
        #Rule: critical events like 'disable_alarm' or 'disable_device' should not be triggered by non-ADMIN users
        if eventName in ['disable_alarm', 'disable_device', 'reboot'] and userRole == 'ADMIN':
            self.logAnomaly(timestamp, "INFO", f"User {userId} with role {userRole} triggered critical event {eventName}")
            return False
        elif eventName in ['disable_alarm', 'disable_device', 'reboot'] and userRole != 'ADMIN':
            self.logAnomaly(timestamp, "ALERT", f"User {userId} with role {userRole} tried to trigger critical event {eventName}")
            return True

        return flag


