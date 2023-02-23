from .models import Exemplo
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import generics, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from rest_framework_simplejwt.authentication import JWTAuthentication

from .serializers import UserSerializer, ExemploSerializer


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

class UserRegistrationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user = User.objects.get(username=serializer.data['username'])
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        response_data = {'token': token}
        return Response(response_data)

class ExemploViewSet(viewsets.ModelViewSet):
    queryset = Exemplo.objects.all()
    serializer_class = ExemploSerializer

class ExampleView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        # Implementação da lógica do método GET
        return Response({'message': 'GET realizado com sucesso!'})

    def post(self, request, format=None):
        # Implementação da lógica do método POST
        return Response({'message': 'POST realizado com sucesso!'})