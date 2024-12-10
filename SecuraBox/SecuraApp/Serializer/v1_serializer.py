from rest_framework import serializers
from SecuraApp.models.v1_models import *
from django.contrib.auth import authenticate
from django.utils import timezone




class CustomUserRegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(label='Password', write_only=True, style={'input_type': 'password'})
    password2 = serializers.CharField(label = 'Comfirm Password', write_only=True, style={'input_type': 'password'})

    class Meta:
        model = CustomUser
        fields = ['email', 'password1', 'password2']
        
        def validate_email(self, value):
            if CustomUser.objects.filter(email= value).exists():
                raise serializers.ValidationError('Email Already In Use')
            return value
       
    def validate(self, data):
        if data['password1'] != data['password1']:
            raise serializers.ValidationError('Password Do Not Match')
        return data
    

    def create(self, validated_data):
        validated_data.pop('password2')
        user = CustomUser.objects.create_user(
            email = validated_data['email'],
            password = validated_data['password1'],
            
        )
        return user





class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=4, min_length=4)

    def validate(self, attrs):
        otp = attrs.get('otp')
        user = self.context['user']
        if user.otp != otp:
            raise serializers.ValidationError('Invalid OTP')
        if not user.otp_expires_at:
            raise serializers.ValidationError('OTP expiration time is missing')

        if timezone.now() > user.otp_expires_at:
            raise serializers.ValidationError('OTP has expired')

        return attrs


    

class createPinSerializer(serializers.ModelSerializer):
    pin = serializers.CharField(write_only=True, min_length=4, max_length=4)

    class Meta:
        model = Pin
        fields = ['pin']

    def validate_pin(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("PIN must be a 4-digit number.")
        return value
    

    def create(self, validated_data):
        user = self.context['request'].user
        pin_instance, created = Pin.objects.get_or_create(user=user)
        pin_instance.set_pin(validated_data['pin'])
        pin_instance.save()
        return pin_instance
    

    def update(self, instance, validated_data):
        instance.set_pin(validated_data['pin'])
        instance.save()
        return instance

       

        


class CustomuserLoginSerialzer(serializers.ModelSerializer):
    email = serializers.CharField (max_length = 100)
    password = serializers.CharField(label='Password', write_only=True, style={'input_type': 'password'})
    class Meta:
        model = CustomUser
        fields = ['email', 'password']  
        
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            request = self.context.get('request')
            user = authenticate(request=request, username=email, password= password)

            if not user:
                raise serializers.ValidationError('Invalid Credidentials')
                
        else:
            raise serializers.ValidationError('Must Include Email And Password')
        attrs['user'] = user
        return attrs
    


class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

 
        if not check_password(old_password, user.password):
            raise serializers.ValidationError({"old_password": "Old password is incorrect."})
        if new_password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})


        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})

        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.password = make_password(new_password)
        user.save()
        return user





class PinResetSerializer(serializers.Serializer):
    old_pin = serializers.CharField(write_only=True, max_length=4)
    new_pin = serializers.CharField(write_only=True, max_length=4)
    confirm_pin = serializers.CharField(write_only=True, max_length=4)

    def validate(self, attrs):
        user = self.context['request'].user
        try:
            user_pin = user.pin
        except Pin.DoesNotExist:
            raise serializers.ValidationError({"old_pin": "User does not have a PIN set."})
        old_pin = attrs.get('old_pin')
        new_pin = attrs.get('new_pin')
        confirm_pin = attrs.get('confirm_pin')

        if not user_pin.verify_pin(old_pin):
            raise serializers.ValidationError({"old_pin": "Old PIN is incorrect."})

        if new_pin != confirm_pin:
            raise serializers.ValidationError({"confirm_pin": "New PIN and confirmation PIN do not match."})

        if not new_pin.isdigit() or len(new_pin) != 4:
            raise serializers.ValidationError({"new_pin": "PIN must be a 4-digit numeric value."})

        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        user_pin = user.pin
        user_pin.set_pin(self.validated_data['new_pin'])
        user_pin.save()

        return user



class SocialmediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMedia
        fields = [ 'id', 'platform', 'email', 'phone_number', 'password', 'profile_url']


        


class MailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mail
        fields = [ 'id', 'platform','email', 'phone_number', 'password', 'mail_url']


    def create(self, validated_data):
        password = validated_data.pop('password')
        instance = super().create(validated_data)
        instance.set_password(password)
        return instance
    
    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data.pop('password'))
        return super().update(instance, validated_data)





class CreditCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditCard
        fields = ['id', 'card_number', 'cardholder_name', 'color', 'expiration_date', 'cvv',]

    def create(self, validated_data):
        return CreditCard.objects.create(**validated_data)
    


class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notes
        fields = [ 'id','title', 'content']
    





class OnlineBankSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnlineBanking
        fields = [ 'id', 'username', 'password', 'bankname']









class  NationalIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = NationalID
        fields = ['id_number', 'id_name', 'country', 'issue_date', 'expiration_date', 'document']





class CertificateSerializer(serializers.ModelSerializer):
    certificate_document = serializers.ImageField() 
    class Meta:
        model = Certificates
        fields = [ 'id',  'certificate_name', 'certificate_document']

    def validate_certificate_document(self, value):
        if value and not value.name.lower().endswith(('pdf', 'jpg', 'jpeg', 'png')):
            raise serializers.ValidationError("Only image files are allowed.")
        return value






class DocumentSerializer(serializers.ModelSerializer):
    file = serializers.ImageField()
    class Meta:
        model = Document
        fields =  [ 'id', 'title', 'description', 'document_file']