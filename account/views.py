from django.shortcuts import render

# Create your views here.
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
import requests
import json
from django.shortcuts import redirect

from django.conf import settings

kakao_secret = settings.KAKAO_SECRET_KEY
kakao_redirect_uri = settings.KAKAO_REDIRECT_URI

from .serializers import UserSerializer
from .models import UserProfile

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
    
class KakaoSignInView(APIView):
    def get(self, request):
        request_uri = f"https://kauth.kakao.com/oauth/authorize?client_id={kakao_secret}&redirect_uri={kakao_redirect_uri}&response_type=code"
        return Response(request_uri, status=status.HTTP_200_OK)
    
class KakaoSignInCallbackView(APIView):
    def get(self, request):
        code = request.GET.get("code")
        request_uri = f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={kakao_secret}&redirect_uri={kakao_redirect_uri}&code={code}"
        response = requests.post(request_uri)
        access_token = response.json().get("access_token")
        user_info = requests.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_info = user_info.json()
        userprofile_info = user_info.get('kakao_account').get('profile')
        try:
            user = User.objects.get(username=user_info.get("id"))
        except User.DoesNotExist:
            user_data = {
                "username": user_info.get("id"),
                "password": "social_login_password",
            }
            user_serializer = UserSerializer(data=user_data)
            if user_serializer.is_valid(raise_exception=True):
                user_serializer.validated_data["password"] = make_password(
                    user_serializer.validated_data["password"]
                )
                user = user_serializer.save()
            user_profile = UserProfile.objects.create(
                user=user,
                is_social_login=True,
                social_provider="kakao",
                nickname=userprofile_info.get("nickname"),
            )
        return set_token_on_response_cookie(user, status_code=status.HTTP_200_OK)