from django.urls import path
from . import views


urlpatterns = [
    path('auth/register/', views.UserRegistration.as_view() , name= 'register'),
    path('auth/verify_account/', views.VerifyUserEmail.as_view(), name = 'verify-email-view'),
    path('auth/login/', views.LoginView.as_view(), name='login_view'),
    path('auth/reset_password/', views.ResetPasswordView.as_view(), name='reset_password_view'),
    path('auth/logout/', views.LogoutBlacklistTokenUpdateView.as_view(), name='logout_view'),
    path('auth/initiate-forgot-password/', views.ForgotPasswordView.as_view(), name='initiate-forgot_password_view'),
    path('auth/register-admin/', views.RegisterAdminView.as_view(), name='register-admin'),
    path('list-all-admins/', views.AllAdminsView.as_view(), name='list-all-admins'),
    path('RUD-admin/', views.AdminDetailView.as_view(), name='RUD-on-admin'),
    path('RUD-user/', views.UserDetailView.as_view(), name='RUD-on-user')
]