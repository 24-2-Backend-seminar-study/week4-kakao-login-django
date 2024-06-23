from django.urls import path
from .views import SignUpView, SignInView, SignOutView


app_name = "account"
urlpatterns = [
    # CBV url path
    path("signup/", SignUpView.as_view()),
    path("signin/", SignInView.as_view()),
    path("signout/", SignOutView.as_view()),
]