from queue import Queue

class DeviceActivity(object):
    AVG_SIZE = 5
    HIGH_THRES_MUL = 5
    LOW_THRES_MUL = 1/10
    ANOMALY_LIMIT = 5

    def __init__(self):
        self.avgInterval = 0
        self.count = 0
        self.prevTimes = Queue()
        self.prevTs = 0
        self.anomalies = 0
        self.nextInactiveCheck = 0

    def updateAvgInterval(self, timestamp):
        if self.prevTs == 0:
            return
        interval = timestamp - self.prevTs
        self.count += 1
        self.prevTimes.put(interval)

        if self.count <= DeviceActivity.AVG_SIZE:
            self.avgInterval += interval
            if self.count == DeviceActivity.AVG_SIZE:
                self.avgInterval /= self.count
        else:
            last_interval = self.prevTimes.get()
            self.avgInterval += (interval - last_interval) / DeviceActivity.AVG_SIZE

    def resetAvg(self):
        self.avgInterval = 0
        self.count = 0
        self.prevTimes = Queue()
        self.prevTs = 0
        self.anomalies = 0

    def checkGreaterThanAvg(self, timestamp):
        # Returns true if the current interval is more than 5x the average interval
        if self.prevTs == 0 or self.count < DeviceActivity.AVG_SIZE:
            return False
        interval = timestamp - self.prevTs
        if interval > self.avgInterval * DeviceActivity.HIGH_THRES_MUL:
            return True
        return False
    
    def checkLessThanAvg(self, timestamp):
        # Returns true if the current interval is 10x smaller than the average interval
        if self.prevTs == 0 or self.count < DeviceActivity.AVG_SIZE:
            return False
        interval = timestamp - self.prevTs
        if interval < self.avgInterval * DeviceActivity.LOW_THRES_MUL:
            return True
        return False
    
    def markAnomaly(self):
        # Marks that there was an anomaly and does not update the avgInterval, only the previous ts
        self.anomalies += 1

    def updatePrevTs(self, timestamp):
        self.prevTs = timestamp

    def getCurInterval(self, timestamp):
        return timestamp - self.prevTs







        

