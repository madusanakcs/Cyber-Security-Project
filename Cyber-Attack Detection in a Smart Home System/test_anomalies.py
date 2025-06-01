import unittest
import time
import random
from instrument import AnomalyDetector  

class TestUnexpectedUser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n-------------------------------------------------------")
        print("Testing for unexpected source logins and activities")
    
        cls.detector = AnomalyDetector()
        now = time.time()
        cls.now = now

        # Register users once for all tests
        cls.detector.instrument("register", "ADMIN", "123", "008777", now, {})
        cls.detector.instrument("register", "USER", "124", "004281", now, {})
        cls.detector.instrument("register", "MANAGER", "125", "002141", now, {})
        cls.detector.instrument("register", "USER", "126", "006426", now, {})

    def setUp(self):
        print("-------------------------------------------------------")

    def test_normal_login_attempts(self):
        print("Testing normal user logins")
        for _ in range(3):
            flagged = self.detector.instrument("login_attempt", "ADMIN", "123", "008777", time.time(), {"status": "success"})
            self.assertFalse(flagged[AnomalyDetector.UNEXPECTED_FLAG])

    def test_infrequent_new_sources_no_flag(self):
        print("Testing infrequent new source logins")
        base_time = self.now
        flagged1 = self.detector.instrument("login_attempt", "USER", "124", "009001", base_time + 100, {"status": "success"})
        flagged2 = self.detector.instrument("login_attempt", "USER", "124", "009002", base_time + 200000, {"status": "success"})
        self.assertFalse(flagged1[AnomalyDetector.UNEXPECTED_FLAG])
        self.assertFalse(flagged2[AnomalyDetector.UNEXPECTED_FLAG])

    def test_multiple_new_sources_trigger_flag(self):
        print("Testing frequent new source logins")
        base_time = self.now
        flagged1 = self.detector.instrument("login_attempt", "MANAGER", "125", "009101", base_time + 10, {"status": "success"})
        flagged2 = self.detector.instrument("login_attempt", "MANAGER", "125", "009102", base_time + 200, {"status": "success"})
        flagged3 = self.detector.instrument("login_attempt", "MANAGER", "125", "009103", base_time + 400, {"status": "success"})
        self.assertFalse(flagged1[AnomalyDetector.UNEXPECTED_FLAG])
        self.assertFalse(flagged2[AnomalyDetector.UNEXPECTED_FLAG])
        self.assertTrue(flagged3[AnomalyDetector.UNEXPECTED_FLAG])

    def test_critical_event_flagged_due_to_recent_new_login(self):
        print("Testing critical events triggered after new source login")
        base_time = self.now
        self.detector.instrument("login_attempt", "ADMIN", "123", "010301", base_time + 10, {"status": "success"})
        flagged = self.detector.instrument("disable_alarm", "ADMIN", "123", "010301", base_time + 30 * 60, {})
        self.assertTrue(flagged[AnomalyDetector.UNEXPECTED_FLAG])

    def test_critical_event_not_flagged_if_login_not_recent(self):
        print("Testing critical events triggered a longer time after new source login")
        base_time = self.now
        self.detector.instrument("login_attempt", "ADMIN", "123", "010401", base_time + 20, {"status": "success"})
        flagged = self.detector.instrument("disable_alarm", "ADMIN", "123", "010401", base_time + 3 * 3600, {})
        self.assertFalse(flagged[AnomalyDetector.UNEXPECTED_FLAG])

class TestDeviceActivity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n-------------------------------------------------------")
        print("Testing for variations in device activity frequency")

    def setUp(self):
        print("-------------------------------------------------------")
        self.detector = AnomalyDetector()
        self.devices = ["temp-sensor-1", "controller-4", "motion-sensor-8"]
        self.source_id = "012842"
        self.user_id = "112"
        self.user_role = "ADMIN"
        self.now = time.time()

    def test_stable_normal_activity_all_devices(self):
        print("Testing stable normal activity (no alerts) for multiple devices")
        base = self.now
        for device_id in self.devices:
            for i in range(10):
                flagged = self.detector.instrument("device_heartbeat", self.user_role, self.user_id,
                                                   self.source_id, base + i * 60, {"device_id": device_id})
                self.assertFalse(flagged[AnomalyDetector.ACTIVITY_FLAG])

    def test_minor_jitter_no_flag(self):
        print("Testing small jitter (±5s) in intervals")
        base = self.now
        device_id = self.devices[0]
        for i in range(10):
            jitter = random.randint(-5, 5)
            ts = base + i * 60 + jitter
            flagged = self.detector.instrument("device_heartbeat", self.user_role, self.user_id,
                                               self.source_id, ts, {"device_id": device_id})
            self.assertFalse(flagged[AnomalyDetector.ACTIVITY_FLAG])

    def test_frequent_activity_flag_after_5(self):
        print("Testing fast reporting: should be flagged after 5 events")
        ts = self.now
        device_id = self.devices[1]
        for i in range(10):
            self.detector.instrument("sensor_report", self.user_role, self.user_id,
                                     self.source_id, ts, {"device_id": device_id})
            ts += 60
        
        for i in range(10):
            flagged = self.detector.instrument("sensor_report", self.user_role, self.user_id,
                                               self.source_id, ts, {"device_id": device_id})
            ts += 5
            
        self.assertTrue(flagged[AnomalyDetector.ACTIVITY_FLAG])

    def test_slow_activity_flag_after_5(self):
        print("Testing slow reporting flagged after 5 events")
        ts = self.now
        device_id = self.devices[2]
        for i in range(10):
            self.detector.instrument("power_report", self.user_role, self.user_id,
                                     self.source_id, ts, {"device_id": device_id})
            ts += 60
        
        for i in range(6):
            flagged = self.detector.instrument("power_report", self.user_role, self.user_id,
                                               self.source_id, ts, {"device_id": device_id})
            ts += 400
        
        self.assertTrue(flagged[AnomalyDetector.ACTIVITY_FLAG])

    def test_inactivity_triggers_on_other_device_call(self):
        print("Testing inactivity triggered by another device activity")
        ts = self.now
        dev_a = self.devices[0]
        dev_b = self.devices[1]

        # Normal device activity
        for i in range(10):
            self.detector.instrument("device_heartbeat", self.user_role, self.user_id,
                                     self.source_id, ts, {"device_id": dev_a})
            ts += 60
        
        # Jump time beyond 5× average (300 + 301)
        ts += 301
        flagged = self.detector.instrument("device_heartbeat", self.user_role, self.user_id,
                                           self.source_id, ts, {"device_id": dev_b})

        self.assertTrue(flagged[AnomalyDetector.ACTIVITY_FLAG], "Inactivity should be flagged")

    def test_reset_clears_activity_alert(self):
        print("Testing reset cancels rate deviation alerts")
        ts = self.now
        device_id = self.devices[2]
        
        # Normal activity
        for i in range(10):
            flagged = self.detector.instrument("data_sync", self.user_role, self.user_id,
                                     self.source_id, ts, {"device_id": device_id})
            ts += 60

        self.assertFalse(flagged[AnomalyDetector.ACTIVITY_FLAG], "Normal operation")
        
        # Abnormal fast intervals
        for i in range(6):
            flagged = self.detector.instrument("data_sync", self.user_role, self.user_id,
                                     self.source_id, ts, {"device_id": device_id})
            ts += 5

        self.assertTrue(flagged[AnomalyDetector.ACTIVITY_FLAG], "Sudden increase in frequency")
        
        # Reset
        flagged = self.detector.instrument("data_sync", self.user_role, self.user_id,
                                           self.source_id, ts, {"device_id": device_id, "status": "reset"})
        ts += 5
        self.assertFalse(flagged[AnomalyDetector.ACTIVITY_FLAG])

        # New pattern after reset should not raise alert
        for i in range(10):
            flagged = self.detector.instrument("data_sync", self.user_role, self.user_id,
                                               self.source_id, ts, {"device_id": device_id})
            ts += 5
            self.assertFalse(flagged[AnomalyDetector.ACTIVITY_FLAG])
 
    
class TestRoleAwareFiltering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n-------------------------------------------------------")
        print("Testing for role aware filtering")

        cls.detector = AnomalyDetector()
        now = time.time()
        cls.now = now

        # Register several users (common to all test cases)
        cls.detector.instrument("register", "ADMIN", "123", "008777", now, {})
        cls.detector.instrument("register", "USER", "124", "004281", now, {})
        cls.detector.instrument("register", "MANAGER", "125", "002141", now, {})
        cls.detector.instrument("register", "USER", "126", "006426", now, {})

    def setUp(self):
        print("-------------------------------------------------------")

    def test_business_hour_login_no_alert_for_admin(self):
        print("Testing business-hour login from new source by ADMIN (should not flag)")
        time_struct = time.localtime(self.now)
        ten_am = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                              10, 0, 0, time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("login_attempt", "ADMIN", "123", "012301", ten_am, {"status": "success"})
        self.assertFalse(flagged[AnomalyDetector.ROLE_FLAG])

    def test_after_hours_login_alert_for_admin(self):
        print("Testing after-hours login from new source by ADMIN (should flag)")
        time_struct = time.localtime(self.now)
        ten_pm = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                              22, 0, 0, time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("login_attempt", "ADMIN", "123", "012302", ten_pm, {"status": "success"})
        self.assertTrue(flagged[AnomalyDetector.ROLE_FLAG])

    def test_firmware_update_by_non_manager(self):
        print("Testing firmware update by USER (should flag)")
        time_struct = time.localtime(self.now)
        test_time = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                                time_struct.tm_hour, time_struct.tm_min, time_struct.tm_sec,
                                time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("update_firmware", "USER", "124", "009999", test_time, {})
        self.assertTrue(flagged[AnomalyDetector.ROLE_FLAG])

    def test_firmware_update_by_manager(self):
        print("Testing firmware update by MANAGER (should not flag)")
        time_struct = time.localtime(self.now)
        test_time = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                                time_struct.tm_hour, time_struct.tm_min, time_struct.tm_sec,
                                time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("update_firmware", "MANAGER", "125", "009998", test_time, {})
        self.assertFalse(flagged[AnomalyDetector.ROLE_FLAG])

    def test_critical_event_by_non_admin(self):
        print("Testing critical event by USER (should flag)")
        time_struct = time.localtime(self.now)
        test_time = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                                time_struct.tm_hour, time_struct.tm_min, time_struct.tm_sec,
                                time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("disable_alarm", "USER", "126", "009997", test_time, {})
        self.assertTrue(flagged[AnomalyDetector.ROLE_FLAG])

    def test_critical_event_by_admin(self):
        print("Testing critical event by ADMIN (should not flag)")
        time_struct = time.localtime(self.now)
        test_time = time.mktime((time_struct.tm_year, time_struct.tm_mon, time_struct.tm_mday,
                                time_struct.tm_hour, time_struct.tm_min, time_struct.tm_sec,
                                time_struct.tm_wday, time_struct.tm_yday, time_struct.tm_isdst))
        flagged = self.detector.instrument("disable_alarm", "ADMIN", "123", "009996", test_time, {})
        self.assertFalse(flagged[AnomalyDetector.ROLE_FLAG])


class TestRateAnomaly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n-------------------------------------------------------")
        print("Testing for rate anomalies")
        print("________________________________________________________")

        cls.detector = AnomalyDetector()
        now = time.time()
        cls.now = now

        # Register users once for all tests
        cls.detector.instrument("register", "ADMIN", "123", "008777", now, {})
        cls.detector.instrument("register", "USER", "124", "004281", now, {})
        cls.detector.instrument("register", "MANAGER", "125", "002141", now, {})
        cls.detector.instrument("register", "USER", "126", "006426", now, {})

    def setUp(self):
        print("-------------------------------------------------------")

    def test_failed_login_user(self):
        print("Testing failed login rate for USER (flag after 6 failures in 60s)")
        base_time = time.time()
        user_id = "user_fail"
        source_id = "src_fail"
        self.detector.instrument("register", "USER", user_id, source_id, base_time, {})
        
        # 5 failures (should not flag)
        for i in range(5):
            result = self.detector.instrument(
                "login_attempt", "USER", user_id, source_id, 
                base_time + i, {"status": "failure"}
            )
            self.assertFalse(result[AnomalyDetector.RATE_FLAG])
        
        # 6th failure (should flag)
        result = self.detector.instrument(
            "login_attempt", "USER", user_id, source_id,
            base_time + 5, {"status": "failure"}
        )
        self.assertTrue(result[AnomalyDetector.RATE_FLAG])

    def test_failed_login_admin(self):
        print("Testing failed login rate for ADMIN (flag after 4 failures in 60s)")
        base_time = time.time()
        user_id = "admin_fail"
        source_id = "src_fail_admin"
        self.detector.instrument("register", "ADMIN", user_id, source_id, base_time, {})
        
        # 10 failures (should not flag)
        for i in range(3):
            result = self.detector.instrument(
                "login_attempt", "ADMIN", user_id, source_id, 
                base_time + i, {"status": "failure"}
            )
            self.assertFalse(result[AnomalyDetector.RATE_FLAG])
        
        # 11th failure (should flag)
        result = self.detector.instrument(
            "login_attempt", "ADMIN", user_id, source_id,
            base_time + 10, {"status": "failure"}
        )
        self.assertTrue(result[AnomalyDetector.RATE_FLAG])
 
    def test_toggle_device_user(self):
        print("Testing toggle device spam for USER (flag after 11 toggles in 30s)")
        base_time = time.time()
        flagged = False
        for i in range(11):  # USER limit is 10 toggles per 30s
            flagged = self.detector.instrument(
                "toggle_device", "USER", "user2", "src3",
                base_time + i * 2,
                {"device_name": "fan"}
            )
        self.assertTrue(flagged[AnomalyDetector.RATE_FLAG])

    def test_toggle_device_admin(self):
        print("Testing toggle device spam for ADMIN (flag after 21 toggles in 30s)")
        base_time = time.time()
        flagged = False
        for i in range(21):  # ADMIN limit is 20 toggles per 30s (2x user limit)
            flagged = self.detector.instrument(
                "toggle_device", "ADMIN", "admin2", "src4",
                base_time + i,
                {"device_name": "light"}
            )
        self.assertTrue(flagged[AnomalyDetector.RATE_FLAG])

    def test_normal_toggle_use(self):
        print("Testing normal toggle use")
        base_time = time.time()
        user_id = 'user3'
        source_id = 'src5'
        self.detector.instrument('register', 'USER', user_id, source_id, base_time, {})

        flagged = False
        for i in range(10):  # Exactly at limit, should NOT flag
            flagged |= self.detector.instrument('toggle_device', 'USER', user_id, source_id, base_time + i * 3, {})[AnomalyDetector.RATE_FLAG]
        self.assertFalse(flagged)

    def test_password_change_rate(self):
        base_time = time.time()
        user_id = "user_pw"
        flagged = False
        for i in range(3):  # More than 2 changes in 30 mins triggers flag
            flagged = self.detector.instrument("password_change", "USER", user_id, "src_pw", base_time + i * 600, {})
        self.assertTrue(flagged[AnomalyDetector.RATE_FLAG])

    def test_device_registration_rate(self):
        print("Testing device registration rate limit")
        base_time = time.time()
        
        # Register a test user first
        self.detector.instrument("register", "USER", "test_user", "test_src", base_time, {})
        
        # Verify registration worked
        self.assertIn("test_user", self.detector.regUsers)
        
        flagged = False
        for i in range(6):  # USER limit is 5 registrations per hour
            result = self.detector.instrument(
                "device_registration",
                "USER",
                "test_user",
                f"src_{i}",
                base_time + i * 600,  # 10 minutes apart
                {"device_id": f"dev_{i}"}
            )
            flagged = flagged or result[AnomalyDetector.RATE_FLAG]  # Capture any True results
        
        self.assertTrue(flagged, "Should flag after exceeding device registration limit")
        




class TestValueAnomaly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n-------------------------------------------------------")
        print("Testing for value anomalies")
        cls.detector = AnomalyDetector()
        cls.timestamp = time.time()
        cls.detector.instrument("register", "USER", "200", "srcA", cls.timestamp, {})

    def setUp(self):
        print("-------------------------------------------------------")
        self.detector = AnomalyDetector()
        self.timestamp = time.time()
        self.detector.instrument("register", "USER", "200", "srcA", self.timestamp, {})

    # ------------------ POWER TESTS ------------------ #

    def test_normal_power_values(self):
        print("Testing normal power readings (no flag expected)")
        for val in [100, 105, 110, 95, 102]:
            flagged = self.detector.instrument(
                'power_reading', 'USER', '200', 'srcA', self.timestamp,
                {'device_id': 'fan1', 'value': val}
            )
            self.assertFalse(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of normal power readings")

    def test_abrupt_power_spike(self):
        print("Testing abrupt power spike (should flag)")
        for i in range(5):
            self.detector.instrument(
                'power_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'fan1', 'value': 100}
            )
        flagged = self.detector.instrument(
            'power_reading', 'USER', '200', 'srcA', self.timestamp + 5,
            {'device_id': 'fan1', 'value': 300}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])

        # print("End of abrupt power spike")

    def test_abrupt_power_drop(self):
        print("Testing abrupt power drop (should flag)")
        for i in range(5):
            self.detector.instrument(
                'power_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'fan1', 'value': 300}
            )
        flagged = self.detector.instrument(
            'power_reading', 'USER', '200', 'srcA', self.timestamp + 5,
            {'device_id': 'fan1', 'value': 0}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of abrupt power drop")

    def test_stuck_power_sensor(self):
        print("Testing stuck power sensor (should flag)")
        for i in range(5):
            self.detector.instrument(
                'power_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'fan1', 'value': 150}
            )
        flagged = self.detector.instrument(
            'power_reading', 'USER', '200', 'srcA', self.timestamp + 6,
            {'device_id': 'fan1', 'value': 150}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of stuck power sensor test")

    # ------------------ TEMPERATURE TESTS ------------------ #

    def test_normal_temperature_values(self):
        print("Testing normal temperature readings (no flag expected)")
        for val in [22.0, 21.5, 22.2, 21.8, 22.1]:
            flagged = self.detector.instrument(
                'temperature_reading', 'USER', '200', 'srcA', self.timestamp,
                {'device_id': 'temp1', 'value': val}
            )
            self.assertFalse(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of normal temperature readings")

    def test_temperature_spike(self):
        print("Testing temperature spike (should flag)")
        for i in range(5):
            self.detector.instrument(
                'temperature_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'temp1', 'value': 25.0}
            )
        flagged = self.detector.instrument(
            'temperature_reading', 'USER', '200', 'srcA', self.timestamp + 6,
            {'device_id': 'temp1', 'value': 35.0}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of temperature spike test")

    def test_temperature_drop(self):
        print("Testing temperature drop (should flag)")
        for i in range(5):
            self.detector.instrument(
                'temperature_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'temp1', 'value': 30.0}
            )
        flagged = self.detector.instrument(
            'temperature_reading', 'USER', '200', 'srcA', self.timestamp + 6,
            {'device_id': 'temp1', 'value': 20.0}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of temperature drop test")

    def test_temperature_out_of_range(self):
        print("Testing out-of-range temperature (should flag)")
        flagged_low = self.detector.instrument(
            'temperature_reading', 'USER', '200', 'srcA', self.timestamp,
            {'device_id': 'temp1', 'value': -50.0}
        )
        flagged_high = self.detector.instrument(
            'temperature_reading', 'USER', '200', 'srcA', self.timestamp + 1,
            {'device_id': 'temp1', 'value': 120.0}
        )
        self.assertTrue(flagged_low[AnomalyDetector.VALUE_FLAG])
        self.assertTrue(flagged_high[AnomalyDetector.VALUE_FLAG])
        # print("End of out-of-range temperature test")

    def test_stuck_temperature_sensor(self):
        print("Testing stuck temperature sensor (should flag)")
        for i in range(5):
            self.detector.instrument(
                'temperature_reading', 'USER', '200', 'srcA', self.timestamp + i,
                {'device_id': 'temp1', 'value': 24.0}
            )
        flagged = self.detector.instrument(
            'temperature_reading', 'USER', '200', 'srcA', self.timestamp + 6,
            {'device_id': 'temp1', 'value': 24.0}
        )
        self.assertTrue(flagged[AnomalyDetector.VALUE_FLAG])
        # print("End of stuck temperature sensor test")

        

if __name__ == '__main__':
    unittest.main()
