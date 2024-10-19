from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from SecuraApp.Views.v1_views import *
from SecuraApp.Adminviews import *

router = DefaultRouter()
router.register(r'register',UsersRegisterViewSet, basename='register')
router.register(r'verifyotp', VerifyOTPViewSet, basename= 'verifyotp')
router.register(r'userLogin', UserLoginViewset, basename= 'login')
router.register(r'socialmedia', SocialmediaViewset, basename= 'socials')
router.register(r'mail', MailViewset, basename= 'mail')
router.register(r'onlinebank', OnlineBankViewset, basename= 'onlinebank')
router.register(r'creditcard', CreditCardViewset, basename= 'creditcard')
router.register(r'nationalID', NationalIDViewset, basename= 'nationalID')
router.register(r'driverslicence', DriverLicenseViewset, basename= 'driverslicence')
router.register(r'certificate', CertificateViewset, basename= 'certificate')
router.register(r'note', NoteViewset, basename= 'note')
router.register(r'document', DocumentViewset, basename= 'document')





# Nested router
register_router = routers.NestedDefaultRouter(router, r'register', lookup = 'register')
register_router.register(r'pin', createPinView, basename= 'register-pin')




# ADMIN USERS
router.register(r'admin-socialmedia', AdminSocialMediaView, basename= 'socialmedia')
router.register(r'admin-mail', AdminMailView, basename= 'admin-mail')
router.register(r'admin-onlinebank',AdminOnlineBankView, basename= 'admin-onlinebank')



urlpatterns = [
    
    path('', include(router.urls)),
    path('', include(register_router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

