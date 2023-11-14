#!/usr/bin/env python3
"""
Basic Auth module
"""

from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    class BasicAuth
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        returns the Base64 part of the Authorization header
        for a Basic Authentication
        """
        if (authorization_header is None or
            not isinstance(authorization_header, str) or
                not authorization_header.startswith("Basic ")):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        returns the decoded value of a Base64 string
        base64_authorization_header
        """
        b64_auth_header = base64_authorization_header
        if b64_auth_header and isinstance(b64_auth_header, str):
            try:
                return base64.b64decode(b64_auth_header).\
                        decode('utf-8')
            except Exception:
                return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        returns the user email and password from the Base64 decoded value
        """
        decoded_64 = decoded_base64_authorization_header
        if (decoded_64 and isinstance(decoded_64, str) and
                ":" in decoded_64):
            email, password = decoded_64.split(":", 1)
            # The 1 as the second arg to the split method limits
            # the split to only one occurrence. This means it will split
            # the string at the first ":" it encounters.
            return email, password
        return None, None

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        returns the User instance based on his email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({'email': user_email})
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
                else:
                    return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        overloads Auth and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        b64_header = self.extract_base64_authorization_header(auth_header)
        decoded = self.decode_base64_authorization_header(b64_header)
        credentials = self.extract_user_credentials(decoded)
        user = self.user_object_from_credentials(
            credentials[0], credentials[1])
        return user