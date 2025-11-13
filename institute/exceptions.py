# institute/exceptions.py

from rest_framework.exceptions import APIException
from rest_framework import status

# ======================================================
# Custom Exception Classes
# ======================================================

class NotAnInstituteException(APIException):
    """Raised when a non-institute user attempts restricted operations."""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Only institute accounts are allowed to perform this action."
    default_code = "not_an_institute"


class DuplicateCourseNameException(APIException):
    """Raised when an institute tries to create a course with a duplicate name."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "A course with this name already exists for your institute."
    default_code = "duplicate_course_name"


class InvalidCourseOwnershipException(APIException):
    """Raised when an institute tries to create or modify a batch for another institute’s course."""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You can only manage batches for your own courses."
    default_code = "invalid_course_ownership"


class UnexpectedInstituteError(APIException):
    """Generic fallback for unexpected issues."""
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "An unexpected error occurred. Please try again later."
    default_code = "unexpected_institute_error"


class InvalidObjectReferenceException(APIException):
    """Raised when a referenced object (e.g., course, student) does not exist."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "The referenced object does not exist or the provided ID is invalid."
    default_code = "invalid_object_reference"
