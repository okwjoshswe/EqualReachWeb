# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('settings/', views.settings_view, name='settings'),
    # path('profile/', views.profile_view, name='profile'),
    # path('change-password/', views.change_password, name='change_password'),
    # path('stats/', views.account_stats, name='account_stats'),
]
