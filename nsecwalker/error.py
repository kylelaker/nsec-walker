class ResolutionError(Exception):
    def __init__(self, msg, name):
        super().__init__(msg)
        self.name = name


class GenericResolutionFailureError(ResolutionError):
    def __init__(self, name):
        super().__init__(f"Unable to lookup NSEC for {name}", name)


class DuplicateNsecError(ResolutionError):
    def __init__(self, name):
        super().__init__(f"Duplicate NSEC records for {name}", name)


class CycleDetectedError(ResolutionError):
    def __init__(self, name):
        super().__init__(f"Cycle detected when querying {name}", name)
