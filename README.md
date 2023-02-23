# login, logout, registro e protegida com roles e permissões usando rest_framework_simplejwt

Certifique-se de que está em um ambiente virtual para evitar conflitos de dependência:

```
python3 -m venv env
source env/bin/activate
```

Certifique-se de ter o pip instalado:

```
python -m ensurepip --upgrade
```

Instale o Django REST framework usando o pip:

```
pip install djangorestframework
```

Crie um projeto Django

```
django-admin startproject nome_do_projeto
```

Adicione 'rest_framework' à lista de `INSTALLED_APPS` em `settings.py` do seu projeto:

```
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework', # adicione esta linha
]
```

Entre no diretório do projeto

```
cd nome_do_projeto
```

Crie um aplicativo Django

```
python manage.py startapp nome_do_aplicativo
```

Abra o arquivo `settings.py` dentro do diretório do projeto e adicione o aplicativo à lista de `INSTALLED_APPS`:

```
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'nome_do_aplicativo',
]
```

1. Instale o pacote rest_framework_simplejwt usando o pip:

```
pip install djangorestframework_simplejwt
```

1. Adicione 'rest_framework_simplejwt.authentication.JWTAuthentication' à lista de autenticação padrão do Django REST framework no arquivo settings.py:

```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}
```

1. Crie uma view para gerar tokens JWT para usuários autenticados. Crie uma nova view chamada 'TokenObtainPairView' que herda de 'TokenObtainPairView' do rest_framework_simplejwt.views.

```
from rest_framework_simplejwt.views import TokenObtainPairView

class TokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
```

Você pode criar um serializer personalizado para retornar informações personalizadas no token JWT, por exemplo, o username do usuário autenticado.

1. Adicione rotas para as views criadas. Em urls.py:

```
from django.urls import path
from .views import TokenObtainPairView, TokenRefreshView, RegisterView, LogoutView

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
]
```

1. Crie uma view para registro de novos usuários. A view deve receber um username, email e password no corpo da requisição POST. Em views.py:

```
from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny

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
```

1. Crie uma view para logout de usuários autenticados. A view deve invalidar o token JWT do usuário. Em views.py:

```
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response(status=status.HTTP_205_RESET_CONTENT)
```

1. Crie um grupo de permissões e atribua permissões a ele. Em models.py:

```
from django.contrib.auth.models import Group, Permission

class Role(Group):
    pass

    class Meta:
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'

class Permission(Permission):
    role = models.ManyToManyField(Role, related_name='permissions')

    class Meta:
        verbose_name = 'Permission'
        verbose_name_plural = 'Permissions'
```

1. Crie um serializer para retornar informações personalizadas no token JWT, incluindo a role do usuário autenticado. Em serializers.py:

```
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Role, Permission

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['role'] = Role.objects.filter(user=user).first().name
        return token
```

1. Crie uma view para verificar se o usuário autenticado tem uma determinada permissão. Em views.py:

```
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class HasPermissionView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, permission):
        user = request.user
        role = Role.objects.filter(user=user).first()
        if role:
            if role.permissions.filter(codename=permission).exists():
                return Response({'has_permission': True})
        return Response({'has_permission': False})
```

1. Adicione rotas para a nova view criada. Em urls.py:

```
urlpatterns = [
    #...
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
]
```

Dessa forma, você pode criar uma API simples de login, logout, registro e protegida com roles e permissões usando rest_framework_simplejwt. Certifique-se de criar as classes de modelo Role e Permission no seu projeto e atribuir permissões a eles, além de modificar as views e serializers conforme necessário para atender aos requisitos do seu projeto.



1. Crie um serializer para o registro de usuários que inclua a role. Em serializers.py:

```
class RegisterSerializer(serializers.ModelSerializer):
    role = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        role_name = validated_data.pop('role')
        role, created = Role.objects.get_or_create(name=role_name)
        user.groups.add(role)
        return user
```

1. Crie uma view para atualizar as informações do usuário autenticado. A view deve receber um username e email no corpo da requisição PUT. Em views.py:

```
class UpdateUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UpdateUserSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user
```

1. Crie um serializer para a atualização de usuários. Em serializers.py:

```
class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']
```

Com esses passos, você criou uma API simples de login, logout, registro, protegida por roles e permissões e atualização de informações do usuário. Certifique-se de configurar as permissões necessárias para as views de acordo com as necessidades do seu projeto.

1. Adicione rotas para as novas views criadas. Em urls.py:

```
lua
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    #...
    path('register/', RegisterView.as_view(), name='register'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
```

1. Adicione a nova view ao arquivo `urls.py` do seu Projecto:

```
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/', include("backend.users.urls"))
]
```

1. Finalmente, teste a API usando um cliente como o Postman ou Insomnia. Certifique-se de configurar as solicitações corretamente e incluir o token JWT em solicitações protegidas.
