from django.shortcuts import render
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, mixins
from rest_framework import generics
from rest_framework.permissions import IsAdminUser
from SecuraApp.models.v1_models import CustomUserManager
from SecuraApp.models.v1_models import *
from rest_framework.response import Response
from rest_framework import status
from .AdminSerializer import *
from rest_framework.permissions import AllowAny, IsAuthenticated





class AdminSocialMediaView(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    serializer_class = AdminSocialmediaSerializer
    queryset = AdminSocialMedia.objects.none()

    def create(self, request):
        user = request.user
        if user.is_superuser or user.is_staff():
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception= True)
            serializer.save()
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a Staff or superuser'}, status= status.HTTP_400_BAD_REQUEST)
        


class AdminMailView(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    serializer_class = AdminMailSerializer
    queryset = AdminMail.objects.none()

    def create(self, request):
        user = request.user
        if user.is_superuser or user.is_staff():
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception= True)
            serializer.save()
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a Staff or superuser'}, status= status.HTTP_400_BAD_REQUEST)
        



class AdminOnlineBankView(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    serializer_class = AdminOnlineBankSerializer
    queryset = AdminOnlineBank.objects.none()

    def create(self, request):
        user = request.user
        if user.is_superuser or user.is_staff():
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception= True)
            serializer.save()
            return Response({'message': 'Created Suceessfully'}, status= status.HTTP_201_CREATED)
        else:
            return Response({'message': 'not a Staff or superuser'}, status= status.HTTP_400_BAD_REQUEST)
        


