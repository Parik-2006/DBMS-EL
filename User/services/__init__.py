import os
from django.conf import settings

CONFIDENCE_THRESHOLD = float(os.environ.get('PARI_CONFIDENCE_THRESHOLD', '0.75'))

def get_confidence_threshold():
    return CONFIDENCE_THRESHOLD

def set_confidence_threshold(threshold):
    global CONFIDENCE_THRESHOLD
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"Threshold must be between 0.0 and 1.0, got {threshold}")
    CONFIDENCE_THRESHOLD = threshold
