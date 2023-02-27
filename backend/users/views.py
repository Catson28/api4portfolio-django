from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from .serializers import RegisterSerializer, MyTokenObtainPairSerializer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                return Response({
                    'user': serializer.data,
                    'message': 'User created successfully',
                }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response(status=status.HTTP_205_RESET_CONTENT)

class HasPermissionView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, permission):
        user = request.user
        role = Role.objects.filter(user=user).first()
        if role:
            if role.permissions.filter(codename=permission).exists():
                return Response({'has_permission': True})
        return Response({'has_permission': False})

class TokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class TokenRefreshAPIView(TokenRefreshView):
    """
    View para renovar o token de autenticação do usuário.
    """
    pass