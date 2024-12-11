from django.utils import timezone
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, mixins
from rest_framework import generics
from django.contrib.auth.hashers import check_password, make_password
from rest_framework_simplejwt.tokens import RefreshToken
from SecuraApp.models.v1_models import *
from rest_framework.response import Response
from rest_framework import status
from SecuraApp.pagination import CustomPageNumberPagination
from SecuraApp.Serializer.v1_serializer import *
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import action
from SecuraApp.emails import *
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from rest_framework.parsers import MultiPartParser, FormParser
from SecuraApp.cloudinary import upload_to_cloudinary








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


#AUTHENTICATED
class PasswordResetView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'success': True,"message": "Password reset successful!"}, status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PinResetView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = PinResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "PIN updated successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UsersLogoutViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer  

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                refresh_token = serializer.validated_data['refresh']
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        


    


# Not AUTHENTICATED  PASSWORD RESET

class RequestOTPView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def post(self, request):
        serializer = RequestOTPTSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                user.otp = generate_otp()
                user.otp_created_at = now()
                user.otp_expires_at = get_otp_expiry()
                user.save()
                # Send OTP via email (email sending logic here)
                return Response({"message": "OTP sent to your email"}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def post(self, request):
        serializer = VerifyOTPTSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = CustomUser.objects.get(email=email, otp=otp)
                if user.otp_expires_at and user.otp_expires_at > now():
                    return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return Response({"error": "Invalid OTP or email"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResetPasswordView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            try:
                user = CustomUser.objects.get(email=email, otp=otp)
                if user.otp_expires_at and user.otp_expires_at > now():
                    user.password = make_password(new_password)
                    user.otp = None  
                    user.save()
                    return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return Response({"error": "Invalid OTP or email"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    




class SocialmediaViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = SocialmediaSerializer
    queryset = SocialMedia.objects.none()
    pagination_class = CustomPageNumberPagination


    def get_queryset(self):
        queryset = SocialMedia.objects.filter(user=self.request.user).order_by('-created_at')
        platform = self.request.query_params.get('platform', None)
        if platform:
            queryset = queryset.filter(platform=platform)
        return queryset

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user_id=user.id) 
            return Response({'message': 'Created Successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a valid user'}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None,  partial=True):
        social_media = get_object_or_404(SocialMedia, pk=pk, user=request.user) 
        serializer = self.serializer_class(social_media, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def platform_filter(self, request):
        platform = request.query_params.get('platform', None)
        if platform:
            social_media_accounts = SocialMedia.objects.filter(platform=platform, user=request.user).order_by('-created_at')
            serializer = self.serializer_class(social_media_accounts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'message': 'Platform parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)









class MailViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = MailSerializer
    queryset = Mail.objects.none()
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        queryset = Mail.objects.filter(user=self.request.user).order_by('-created_at')
        platform = self.request.query_params.get('platform', None)
        if platform:
            queryset = queryset.filter(platform=platform)
        return queryset

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception = True)
            serializer.save(user_id=user.id)
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        mail = get_object_or_404(Mail, pk=pk, user=request.user) 
        serializer = self.serializer_class(mail, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def platform_filter(self, request):
        platform = request.query_params.get('platform', None)
        if platform:
            mail_account = Mail.objects.filter(platform=platform, user=request.user).order_by('-created_at')
            serializer = self.serializer_class(mail_account, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'message': 'Platform parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)

    



class  OnlineBankViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = OnlineBankSerializer
    queryset = OnlineBanking.objects.none()
    pagination_class = CustomPageNumberPagination


    def get_queryset(self):
        return OnlineBanking.objects.filter(user=self.request.user).order_by('-created_at')

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception= True)
            serializer.save(user_id = user.id)
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        onlinebank = get_object_or_404(OnlineBanking, pk=pk, user=request.user) 
        serializer = self.serializer_class(onlinebank, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        



class CreditCardViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CreditCardSerializer
    queryset = CreditCard.objects.none()
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        return CreditCard.objects.filter(user=self.request.user).order_by('-created_at')
        

    def create(self, request):
        user = request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user_id=user.id)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_200_OK)
        else:
            return Response({'message': 'not a valid user'}, status= status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        card = get_object_or_404(CreditCard, pk=pk, user=request.user) 
        serializer = self.serializer_class(card, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        



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
        
        
            

class CertificateViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CertificateSerializer
    queryset = Certificates.objects.none()
    pagination_class = CustomPageNumberPagination
    parser_classes = [MultiPartParser, FormParser] 

    def get_queryset(self):
        return Certificates.objects.filter(user=self.request.user).order_by('-created_at')

    def create(self, request):
        user = self.request.user
        if user.is_authenticated:
            file = request.FILES.get('certificate_document')
            if not file:
                return Response({"error": "File is required"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                upload_result = upload_to_cloudinary(file, folder="certificates", tags=["certificate_upload"])
            except Exception as e:
                return Response({"error": f"Cloudinary upload failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            data = request.data.copy()
            data["certificate_document"] = upload_result["secure_url"]  
            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=user)

            return Response({"message": "Certificate created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

        return Response({"error": "Not a valid user"}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, partial=True):
        user = request.user
        certificate = get_object_or_404(Certificates, pk=pk, user=user)
        file = request.FILES.get('certificate_document')
        if file:
            try:
                upload_result = upload_to_cloudinary(file, folder="certificates", tags=["certificate_update"])
                request.data["certificate_document"] = upload_result["secure_url"] 
            except Exception as e:
                return Response({"error": f"Cloudinary upload failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        serializer = self.serializer_class(certificate, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Certificate updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        






class NoteViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = NoteSerializer
    queryset = Notes.objects.none()
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        return Notes.objects.filter(user=self.request.user).order_by('-created_at')

    def create(self, request):
        user = self.request.user
        if user.is_authenticated or isinstance(user, CustomUser):
            serializers = self.serializer_class(data = request.data)
            serializers.is_valid(raise_exception= True)
            serializers.save(user_id=user.id)
            return Response({'message': 'Created Sucessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Not a Valid User'}, status= status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk=None,  partial=True):
        notes = get_object_or_404(Notes, pk=pk, user=request.user) 
        serializer = self.serializer_class(notes, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        


class DocumentViewset(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = DocumentSerializer
    queryset = Document.objects.none()
    pagination_class = CustomPageNumberPagination
    parser_classes = [MultiPartParser, FormParser]  

    def get_queryset(self):
        return Document.objects.filter(user=self.request.user).order_by('-created_at')

    def create(self, request):
        user = self.request.user
        if user.is_authenticated:
            file = request.FILES.get('document_file')
            if not file:
                return Response({"error": "Document file is required"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                upload_result = upload_to_cloudinary(file, folder="documents", tags=["document_upload"])
            except Exception as e:
                return Response({"error": f"Cloudinary upload failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            data = request.data.copy()
            data["document_file"] = upload_result["secure_url"] 
            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=user)
            return Response({"message": "Document created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"error": "User not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

    def update(self, request, pk=None, partial=True):
        user = request.user
        document = get_object_or_404(Document, pk=pk, user=user)
        file = request.FILES.get('document_file')
        if file:
            try:
                upload_result = upload_to_cloudinary(file, folder="documents", tags=["document_update"])
                request.data["document_file"] = upload_result["secure_url"]  
            except Exception as e:
                return Response({"error": f"Cloudinary upload failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        serializer = self.serializer_class(document, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "Document updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        




def send_notification(user, message):
    notification = Notification.objects.create(user=user, message=message)
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    group_name = f"user_{user.id}"
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'send_notification',
            'message': message,
        }
    )