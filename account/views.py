from django.shortcuts import render

# Create your views here.
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password

from .serializers import UserSerializer

def set_token_on_response_cookie(user, status_code) -> Response:
    token = RefreshToken.for_user(user)
    user = UserSerializer(user).data
    res = Response(user, status=status_code)
    res.set_cookie("refresh_token", value=str(token))
    res.set_cookie("access_token", value=str(token.access_token))
    return res

class SignUpView(APIView):
    def post(self, request):

        user_serializer = UserSerializer(data=request.data)
        if user_serializer.is_valid(raise_exception=True):
            user_serializer.validated_data["password"] = make_password(
                user_serializer.validated_data["password"]
            )
            user = user_serializer.save()
            user.save()

        return set_token_on_response_cookie(user, status_code=status.HTTP_201_CREATED)

class SignInView(APIView):
    def post(self, request):
        user = User.objects.filter(username=request.data["username"]).first()
        if user is None:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if not user.check_password(request.data["password"]):
            return Response({"message": "Invalid password"}, status=status.HTTP_401_UNAUTHORIZED)

        return set_token_on_response_cookie(user, status_code=status.HTTP_200_OK)
    
class SignOutView(APIView):
    def post(self, request):
        if not request.user.is_authenticated:
            return Response(
                {"detail": "please signin"}, status=status.HTTP_401_UNAUTHORIZED
            )
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"detail": "no refresh token"}, status=status.HTTP_400_BAD_REQUEST
            )
        RefreshToken(refresh_token).blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)