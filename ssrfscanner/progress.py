"""Scan progress tracking across attack phases."""


class ScanProgress:
    def __init__(self):
        self.phases = {
            'Local IP': 0,
            'Cloud Metadata': 0,
            'Protocol': 0,
            'Encoded': 0,
            'Parameter': 0,
            'Port Scan': 0,
            'DNS Rebinding': 0,
            'CRLF Injection': 0,
            'Scheme Confusion': 0,
            'Remote': 0
        }
        self.current_phase = None
        self.total_phases = len(self.phases)
        self.phase_weight = {
            'Local IP': 0.20,           # 20% of total weight
            'Cloud Metadata': 0.12,     # 12%
            'Protocol': 0.12,           # 12%
            'Encoded': 0.08,            # 8%
            'Parameter': 0.08,          # 8%
            'Port Scan': 0.08,          # 8%
            'DNS Rebinding': 0.08,      # 8%
            'CRLF Injection': 0.10,     # 10%
            'Scheme Confusion': 0.10,   # 10%
            'Remote': 0.04              # 4%
        }

    def update_phase(self, phase, progress):
        self.phases[phase] = progress
        self.current_phase = phase

    def get_total_progress(self):
        total = 0
        for phase, weight in self.phase_weight.items():
            total += self.phases[phase] * weight
        return total * 100

