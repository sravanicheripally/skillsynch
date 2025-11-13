from rest_framework.exceptions import APIException
from rest_framework import viewsets, generics, permissions, status

class NotAStudentException(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You must be logged in as a student to access this resource."
    default_code = "not_a_student"


class CourseNotAvailableException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "The requested course is not available or not approved."
    default_code = "course_not_found"


class BatchNotAvailableException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "The requested batch is not available or not active."
    default_code = "batch_not_found"


class DuplicateEnrollmentException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "You are already enrolled in this batch."
    default_code = "duplicate_enrollment"


class UnexpectedErrorException(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "An unexpected error occurred. Please try again later."
    default_code = "unexpected_error"
    
class InvalidObjectException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "The requested object does not exist or the provided ID is invalid."
    default_code = "invalid_object"