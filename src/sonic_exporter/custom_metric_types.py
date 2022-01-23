import prometheus_client as prom

class CustomCounter(prom.Counter):
    def set(self, value):
        """Set gauge to the given value."""
        self._raise_if_not_observable()
        self._value.set(float(value))

    def _child_samples(self):
        return (("_total", {}, self._value.get(), None, self._value.get_exemplar()),)


