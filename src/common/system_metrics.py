from collections import deque

import psutil


class SystemMetricsTracker:
    def __init__(self, max_samples: int = 120):
        self.cpu_samples = deque(maxlen=max_samples)
        self.memory_samples = deque(maxlen=max_samples)

        # Prime psutil CPU measurement
        psutil.cpu_percent(interval=None)

    def sample(self) -> None:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent

        self.cpu_samples.append(cpu)
        self.memory_samples.append(memory)

    def average_cpu(self) -> float:
        if not self.cpu_samples:
            return 0.0
        return sum(self.cpu_samples) / len(self.cpu_samples)

    def average_memory(self) -> float:
        if not self.memory_samples:
            return 0.0
        return sum(self.memory_samples) / len(self.memory_samples)