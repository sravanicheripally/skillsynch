from rest_framework import serializers
from datetime import date

class DateRangeValidator:
    """
    Validates:
    1. End date must be after start date.
    2. Start and end dates must not be in the past.
    """

    def __call__(self, attrs):
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')

        # Only validate if both dates are provided
        if start_date and end_date:
            today = date.today()

            # Rule 1: End date must be after start date
            if end_date <= start_date:
                raise serializers.ValidationError({
                    'end_date': 'End date must be after the start date.'
                })

            # Rule 2: Dates should not be in the past
            if start_date < today:
                raise serializers.ValidationError({
                    'start_date': 'Start date cannot be in the past.'
                })

            if end_date < today:
                raise serializers.ValidationError({
                    'end_date': 'End date cannot be in the past.'
                })
