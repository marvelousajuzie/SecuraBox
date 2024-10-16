from rest_framework import serializers
from SecuraApp.models.v1_models import *
from django.contrib.auth import authenticate



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





class VerifyEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField



    

class createPinSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pin
        fields = ['user', 'pin']

       

        


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
            user = authenticate(username=email, password= password)

            if not user:
                raise serializers.ValidationError('Invalid Credidentials')
                
        else:
            raise serializers.ValidationError('Must Include Email And Password')
        attrs['user'] = user
        return attrs
    



class SocialmediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMedia
        fields = [ 'email', 'phone_number', 'password', 'profile_url']
        


class MailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mail
        fields = ['email', 'phone_number', 'password', 'mail_url']



class OnlineBankSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnlineBanking
        fields = ['account_number', 'phone_number', 'password']



class CreditCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditCard
        fields = ['bank_name', 'card_number','cardholder_name','expiration_date', 'cvv']





class  NationalIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = NationalID
        fields = ['id_number', 'id_name', 'country', 'issue_date', 'expiration_date', 'document']






class DriversLicenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriversLicense
        fields = ['license_number', 'id_name', 'country','expiration_date', 'document']




class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificates
        fields = ['issuing_Organization', 'certificateID', 'certificate_name', 'certificate_url', 'issue_date', 'issued_by', 'document']



class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notes
        fields = ['title', 'content']



class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ['title', 'description', 'file']