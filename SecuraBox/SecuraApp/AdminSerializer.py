from rest_framework import serializers
from SecuraApp.models.v1_models import *
from django.contrib.auth import authenticate




# class AdminSocialmediaSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = AdminSocialMedia
#         fields = [ 'logo', 'platform_name']



class AdminMailSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminMail
        fields = ['logo', 'mail_name']


class AdminOnlineBankSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminOnlineBank
        fields = ['logo', 'bank_name']