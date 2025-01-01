from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from SecuraApp.Views.v1_views import *
<<<<<<< HEAD
=======
from SecuraApp.Adminviews import *
>>>>>>> origin/main

router = DefaultRouter()
router.register(r'register',UsersRegisterViewSet, basename='register')
router.register(r'verifyotp', VerifyOTPViewSet, basename= 'verifyotp')
<<<<<<< HEAD
router.register(r'resendcode', ResendOTPViewSet, basename= 'resendcode')
=======
>>>>>>> origin/main
router.register(r'createpin', createPinView, basename= 'create-pin')
router.register(r'verify', VerifyPinView, basename= 'verify-pin')
router.register(r'userlogin', UsersLoginViewSet, basename= 'login')
router.register(r'userlogout', UsersLogoutViewSet, basename= 'logout')
router.register(r'resetmasterpassword',PasswordResetView, basename='resetpassword')
router.register(r'pinreset',PinResetView, basename='pinreset')
<<<<<<< HEAD
=======
router.register(r'notauthenticatedpasswordreset',ResetPasswordView, basename='notauthenticatedpasswordreset')
>>>>>>> origin/main
router.register(r'socialmedia', SocialmediaViewset, basename= 'socials')
router.register(r'mail', MailViewset, basename= 'mail')
router.register(r'onlinebank', OnlineBankViewset, basename= 'onlinebank')
router.register(r'creditcard', CreditCardViewset, basename= 'creditcard')
router.register(r'nationalID', NationalIDViewset, basename= 'nationalID')
router.register(r'certificate', CertificateViewset, basename= 'certificate')
router.register(r'note', NoteViewset, basename= 'note')
router.register(r'document', DocumentViewset, basename= 'document')





<<<<<<< HEAD
#UN AUTHENTICATED PASSWORD RESET


router.register(r'requestotp',RequestOTPViewSet, basename='requestotp')
# router.register(r'verifyrequestotp',VerifyOTPViewSet, basename='verifyrequestotp')
router.register(r'setmasterpassword',SetMasterPasswordViewSet, basename='setmasterpassword')
=======
>>>>>>> origin/main






<<<<<<< HEAD
=======
# ADMIN USERS
router.register(r'admin-onlinebank',AdminOnlineBankView, basename= 'admin-onlinebank')


>>>>>>> origin/main

urlpatterns = [
    
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

