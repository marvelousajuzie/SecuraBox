from django.utils import timezone
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, mixins
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from SecuraApp.models.v1_models import *
from rest_framework.response import Response
from rest_framework import status
from SecuraApp.Serializer.v1_serializer import *
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import action
from SecuraApp.emails import *








# CREATE ACCOUNT
class UsersRegisterViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = CustomUserRegisterSerializer

    def create(self, request, *args, **Kwargs):                                    
        serializer = self.serializer_class(data= request.data)
        if serializer.is_valid(raise_exception= True):
         user = serializer.save()
         send_otp_via_email(serializer.data['email']),
         return Response({ 'message': 'Registered Sucessfully An Otp has been sent to your email'}, status=status.HTTP_200_OK)
        return Response({'message': 'User already exists. Please Log In'}, status=status.HTTP_400_BAD_REQUEST)







# VERIFY OTP FOR  LOGIN ACCOUNT
class VerifyOTPViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        purpose = request.data.get('purpose')

        try:
            user = CustomUser.objects.get(email=email)
            if user.otp == otp and user.otp_expires_at > timezone.now():
                if purpose == 'register':
                     user.is_active = True
                     user.otp = None
                     user.otp_expires_at = None
                     user.save()
                     refresh = RefreshToken.for_user(user)
                     return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'message': 'OTP verified successfully!'
                    }, status=status.HTTP_200_OK)
                
                elif purpose == 'login':
                    user.otp = None
                    user.otp_expires_at = None
                    user.save()
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'message': 'OTP verified successfully!'
                        }, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'Invalid purpose specified.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)





class createPinView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = createPinSerializer 
    
    def create(self, request, *args, **kwargs):
        serializer= self.get_serializer(data= request.data, context={'request': request})
        if serializer.is_valid(raise_exception = True):
            serializer.save()
            return Response({'message': 'Pin Created Sucessfully'}, status= status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class VerifyPinView(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = createPinSerializer 

    @action(detail=False, methods=['post'], url_path='verifypin', url_name='verify-pin')
    def verify_pin(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            pin = serializer.validated_data.get("pin")
            
            try:
                pin_instance = Pin.objects.get(user=request.user)
                if pin_instance.verify_pin(pin):
                    return Response({"message": "PIN verified successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "Invalid PIN."}, status=status.HTTP_400_BAD_REQUEST)
            except Pin.DoesNotExist:
                return Response({"error": "PIN not set for this user."}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# LOGIN ACCOUNT
class UsersLoginViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = CustomuserLoginSerialzer

    def create(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            send_otp_via_email(user.email)
            return Response({
                'message': 'OTP sent to your email for verification. Please enter OTP to complete login.'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







    




class SocialmediaViewset(viewsets.ModelViewSet):
    # permission_classes = [IsAuthenticated]
    serializer_class = SocialmediaSerializer
    queryset = SocialMedia.objects.all()

    # def get_queryset(self):
    #     return SocialMedia.objects.filter(user=self.request.user)

    # def create(self, request):
    #     # user = request.user
    #     # if user.is_authenticated or isinstance(user, CustomUser):
    #         serializer = self.serializer_class(data=request.data)
    #         serializer.is_valid(raise_exception=True)
    #         serializer.save() 
    #         return Response({'message': 'Created Successfully'}, status=status.HTTP_201_CREATED)
    #     # else:
    #     #     return Response({'message': 'Not a valid user'}, status=status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        social_media = get_object_or_404(SocialMedia, pk=pk, user=request.user) 
        serializer = self.serializer_class(social_media, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)









class MailViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = MailSerializer
    queryset = Mail.objects.all()


    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception = True)
            serializer.save()
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        social_media = get_object_or_404(SocialMedia, pk=pk, user=request.user) 
        serializer = self.serializer_class(social_media, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



class  OnlineBankViewset(viewsets.ModelViewSet):
    serializer_class = OnlineBankSerializer
    queryset = OnlineBanking.objects.all()


    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception= True)
            serializer.save(user_id = user.id)
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)



class CreditCardViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CreditCardSerializer
    queryset = CreditCard.objects.none()

    def get_queryset(self):
        return CreditCard.objects.filter(user=self.request.user)
        

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user_id=user.id)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)
        



class NationalIDViewset(viewsets.ModelViewSet):
    serializer_class = NationalIDSerializer
    queryset = NationalID.objects.all()

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid()
            serializers.save(user = user)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        


class DriverLicenseViewset(viewsets.ModelViewSet):
    serializer_class = DriversLicenseSerializer
    queryset = DriversLicense.objects.all()

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user = user)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        
            

class CertificateViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CertificateSerializer
    queryset = Certificates.objects.none()

    def get_queryset(self):
        return Certificates.objects.filter(user=self.request.user)

    def create(self, request):
        user = self.request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user_id=user.id)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        

class NoteViewset(viewsets.ModelViewSet):
    serializer_class = NoteSerializer
    queryset = Notes.objects.all()

    def create(self, request):
        user = self.request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user = user)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        


class DocumentViewset(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    queryset = Document.objects.all()

    def create(self, request):
        user = self.request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user = user)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        