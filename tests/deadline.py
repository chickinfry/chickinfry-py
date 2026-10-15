from dataclasses import dataclass


@dataclass
class Clock:
    now: float = 0.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = round(self.now + seconds, 9)
