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
django-admin startproject backend
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
cd backend
```

Crie um aplicativo Django

```
python ../manage.py startapp authentication
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
    'rest_framework',
    'backend.authentication',
]
```

Nao se esquecer de inserir o nome do projeco no ficheiro apps.py por causa da forma como criamos os aplicativos:

```
from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "backend.authentication"
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

Abra o arquivo `settings.py` dentro do diretório do projeto e adicione o aplicativo à lista de `INSTALLED_APPS`:

```
INSTALLED_APPS = [
    ...,
    'rest_framework_simplejwt',
]
```

###	Iniciando

1. Adicione ao projecto a rota **api/** para as sub rotas criadas na api em questao no arquivo urls.py do projecto:

```

from django.urls import path, include

urlpatterns = [
    path('api/', include("backend.authentication.urls"))
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/', include("backend.users.urls"))
]
```



> Crie o arquivo **authentication/urls.py**

1. Adicione a rota /**register** para a view que sera criada. Em urls.py:

```
from django.urls import path
from .views import RegisterView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
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

1. Para atender às necessidades específicas da aplicação cria-se este serialize. Em serializers.py:

```
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Role, Permission


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



1. Crie uma view para gerar tokens JWT para usuários autenticados. Crie uma nova view chamada 'TokenObtainPairView' que herda de 'TokenObtainPairView' do rest_framework_simplejwt.views.

```
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer

class TokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
```

Você pode criar um serializer personalizado para retornar informações personalizadas no token JWT, por exemplo, o username do usuário autenticado.

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

1. Crie um grupo de permissões e atribua permissões a ele. Em models.py:

```
from django.db import models
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

1. Se isso resultar em erro coloque este

```
from django.db import models
from django.contrib.auth.models import Group, Permission

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField(
        Permission, related_name='permissions_role')

    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=50, unique=True)
    code = models.CharField(max_length=10, unique=True)
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name='role_permissions')

    def __str__(self):
        return self.name
```

> ​	`python manage.py runserver`



1. Adicione a rota /**login** para a view que sera criada. Em urls.py:

```
from rest_framework_simplejwt.views import TokenObtainPairView,


urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView,

from .views import RegisterView,

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
]
```

1. Adicione a rota /**refresh** para a view que sera criada. Em urls.py:

```
from rest_framework_simplejwt.views import TokenRefreshView,

urlpatterns = [
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import RegisterView,

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
```

1. Adicione a rota /**protected** para a view que sera criada. Em urls.py:

```
from .views import ProtectedView,

urlpatterns = [
    path('protected/', ProtectedView.as_view(), name='protected'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import RegisterView, ProtectedView,

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
]
```

- Nome: `ProtectedView`
- URL: `/protected/`
- Método HTTP: GET
- Parâmetros:
  - Headers:
    - `Authorization: Bearer <token>`: um token de acesso válido emitido para um usuário autenticado.
- Descrição: esta view é uma rota protegida que requer autenticação para acessar. Quando um usuário autenticado faz uma solicitação GET para esta rota, ela retorna uma mensagem de resposta que confirma que o usuário foi autenticado com sucesso.

Aqui está o código-fonte da view:

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        content = {'message': 'Você está autenticado!'}
        return Response(content)
```

A view herda da classe `APIView` do Django REST Framework e define a permissão `IsAuthenticated` para proteger a rota. Quando um usuário autenticado faz uma solicitação GET para a rota, o método `get` é chamado e retorna uma mensagem de resposta simples que confirma que o usuário está autenticado.

1. Adicione a rota /**has_role/<str:role>/** para a view que sera criada. Em urls.py:

```
from .views import HasRoleView,

urlpatterns = [
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView,
    ProtectedView,
    HasRoleView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
]
```

A view referente ao endpoint `has_role/<str:role>/` verifica se o usuário autenticado tem uma determinada função (role) atribuída a ele. Se o usuário tiver a função, a view retornará um código de status HTTP 200 (OK) e uma mensagem indicando que o usuário tem a função. Caso contrário, a view retornará um código de status HTTP 403 (Proibido) e uma mensagem indicando que o usuário não tem a função.

Aqui está o código da view:

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class HasRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, role):
        user = request.user
        if user.has_role(role):
            message = f"User {user.username} has the role {role}."
            return Response({"message": message})
        else:
            message = f"User {user.username} does not have the role {role}."
            return Response({"message": message}, status=403)
```

A view herda da classe `APIView` do Django REST Framework e define a classe `permission_classes` como `IsAuthenticated` para garantir que apenas usuários autenticados possam acessar a view. O método `get()` extrai o usuário da requisição e usa o método `has_role()` do modelo personalizado de usuário para verificar se o usuário tem a função (role) especificada. Se o usuário tiver a função, uma mensagem indicando isso é retornada com o código de status HTTP 200. Caso contrário, uma mensagem indicando que o usuário não tem a função é retornada com o código de status HTTP 403.



1. Adicione a rota /**has_permission/<str:permission>/** para a view que sera criada. Em urls.py:

```
from .views import HasPermissionView,

urlpatterns = [
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView,
    ProtectedView,
    HasRoleView,
    HasPermissionView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
]
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



1. Adicione a rota /**update_user** para a view que sera criada. Em urls.py:

```
from .views import UpdateUserView,

urlpatterns = [
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView,
    ProtectedView,
    HasRoleView,
    HasPermissionView,
    UpdateUserView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
]
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





1. Adicione a rota /**update_user** para a view que sera criada. Em urls.py:

```
from .views import LogoutView

urlpatterns = [
    path('logout/', LogoutView.as_view(), name='auth_logout'),
]
```

>  Deixando o arquivo **urls.py** desta forma:

```
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView,
    ProtectedView,
    HasRoleView,
    HasPermissionView,
    UpdateUserView,
    LogoutView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
]
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

Criar o banco de dados

```pyt
python manage.py makemigrations
python manage.py migrate
# Ctrl+C
```

> ​	Ate aqui ja pode **commitar**, Criar novo **branch**  Feacture e efectuar o checkout dele

###	Obs: codigos adicionais

A classe `TokenRefreshView` do `rest_framework_simplejwt` é responsável por renovar o token de autenticação do usuário. Aqui está um exemplo de como implementar essa view na sua aplicação:

```
from rest_framework_simplejwt.views import TokenRefreshView

class TokenRefreshAPIView(TokenRefreshView):
    """
    View para renovar o token de autenticação do usuário.
    """
    pass
```

Observe que, como estamos herdando da classe `TokenRefreshView` do `rest_framework_simplejwt`, não precisamos definir a lógica para renovar o token. A classe já implementa esse comportamento para nós.



Lembre-se de que, para usar a view `TokenRefreshView`, o token de autenticação deve ter um tempo de vida configurado. Isso é feito na configuração do `rest_framework_simplejwt`, por meio do parâmetro `ACCESS_TOKEN_LIFETIME`. Por exemplo:

```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'login_attempts': '5/day',
        'signup_attempts': '3/day',
    },
    'SIMPLE_JWT': {
        'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
        'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
        'ROTATE_REFRESH_TOKENS': True,
    }
}
```

1. Adicione rotas para as novas views criadas. Em urls.py:

```
from rest_framework_simplejwt.views import TokenRefreshView
from .views import TokenRefreshAPIView

urlpatterns = [
    #...
    path('register/', RegisterView.as_view(), name='register'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/refresh/', TokenRefreshAPIView.as_view(), name='token_refresh'),
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

####	E se aparecer este erro:

```
users.Permission.role: (fields.E302) Reverse accessor 'Role.permissions' for 'users.Permission.role' clashes with field name 'users.Role.permissions'.
        HINT: Rename field 'users.Role.permissions', or add/change a related_name argument to the definition for field 'users.Permission.role'.
users.Permission.role: (fields.E303) Reverse query name for 'users.Permission.role' clashes with field name 'users.Role.permissions'.
        HINT: Rename field 'users.Role.permissions', or add/change a related_name argument to the definition for field 'users.Permission.role'.
```

> ​	Corruja desta Maneira

Esse erro ocorre porque você tem um conflito de nomes na sua modelagem de permissões e roles. O erro sugere que você renomeie o campo `permissions` na classe `Role` ou altere o nome da relação inversa na classe `Permission`.

Uma solução para esse erro é definir o parâmetro `related_name` nos campos `ForeignKey` da sua classe `Permission` e `Role`. Isso permite que você especifique um nome personalizado para a relação inversa, evitando assim o conflito de nomes.

Por exemplo, você pode definir o `related_name` como `permissions_role` na classe `Role` e `related_name` como `role_permissions` na classe `Permission`, dessa forma:

```
class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField(
        Permission, related_name='permissions_role')

    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=50, unique=True)
    code = models.CharField(max_length=10, unique=True)
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name='role_permissions')

    def __str__(self):
        return self.name
```

Com essa alteração, o Django agora irá criar as relações inversas com os nomes `permissions_role` e `role_permissions`, evitando assim o conflito de nomes e resolvendo o erro.

1. Finalmente, teste a API usando um cliente como o Postman ou Insomnia. Certifique-se de configurar as solicitações corretamente e incluir o token JWT em solicitações protegidas.

##	Arquivo de rotas urls.py final

Claro, aqui está o código completo do arquivo `urls.py` com todas as rotas criadas anteriormente:

```
python
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView,
    ProtectedView,
    HasRoleView,
    HasPermissionView,
    UpdateUserView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('has_role/<str:role>/', HasRoleView.as_view(), name='has_role'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
]
```

Este arquivo de urls contém as rotas para as seguintes funcionalidades:

- `register/`: Rota para registro de novos usuários.
- `login/`: Rota para autenticação e obtenção do token JWT.
- `refresh/`: Rota para renovação do token JWT.
- `protected/`: Rota protegida que exige autenticação para ser acessada.
- `has_role/<str:role>/`: Rota que verifica se o usuário autenticado possui um papel específico.
- `has_permission/<str:permission>/`: Rota que verifica se o usuário autenticado possui uma permissão específica.
- `update_user/`: Rota para atualizar informações do usuário autenticado.

Cada rota tem um nome associado, que pode ser usado para gerar URLs reversas para essa rota em outras partes do código Django.

##	Formas de acessar todos endpoints

aqui estão as instruções para acessar cada rota através do Postman:

1. `register/` - Rota para registro de novos usuários.

- Tipo de requisição: POST
- URL: `http://localhost:8000/api/register/`
- Corpo da requisição (exemplo):

```
perl
{
    "username": "fulano",
    "email": "fulano@example.com",
    "password": "senha123",
    "confirm_password": "senha123",
    "roles": ["admin"],
    "permissions": ["can_view_users"]
}
```

O campo `roles` é opcional e pode ser usado para atribuir papéis ao usuário recém-criado. O campo `permissions` também é opcional e pode ser usado para atribuir permissões ao usuário recém-criado.

1. `login/` - Rota para autenticação e obtenção do token JWT.

- Tipo de requisição: POST
- URL: `http://localhost:8000/api/login/`
- Corpo da requisição (exemplo):

```
json
{
    "username": "fulano",
    "password": "senha123"
}
```

A resposta da requisição incluirá um token JWT, que deve ser usado para acessar rotas protegidas.

1. `refresh/` - Rota para renovação do token JWT.

- Tipo de requisição: POST
- URL: `http://localhost:8000/api/refresh/`
- Corpo da requisição (exemplo):

```
json
{
    "refresh": "<refresh_token>"
}
```

O campo `refresh` deve conter o token JWT de atualização que foi fornecido anteriormente.

1. `protected/` - Rota protegida que exige autenticação para ser acessada.

- Tipo de requisição: GET
- URL: `http://localhost:8000/api/protected/`
- Cabeçalho da requisição:
  - `Authorization: Bearer <access_token>` O campo `access_token` deve conter o token JWT de acesso que foi fornecido anteriormente.

1. `has_role/<str:role>/` - Rota que verifica se o usuário autenticado possui um papel específico.

- Tipo de requisição: GET
- URL: `http://localhost:8000/api/has_role/<role>/`
- Cabeçalho da requisição:
  - `Authorization: Bearer <access_token>` O campo `access_token` deve conter o token JWT de acesso que foi fornecido anteriormente.

1. `has_permission/<str:permission>/` - Rota que verifica se o usuário autenticado possui uma permissão específica.

- Tipo de requisição: GET
- URL: `http://localhost:8000/api/has_permission/<permission>/`
- Cabeçalho da requisição:
  - `Authorization: Bearer <access_token>` O campo `access_token` deve conter o token JWT de acesso que foi fornecido anteriormente.



1. `update_user/` - Método HTTP: `PUT`

Corpo da requisição:

```
{
    "email": "newemail@example.com",
    "first_name": "New",
    "last_name": "Name",
    "password": "newpassword"
}
```

Headers da requisição:

```
makefile
Authorization: Bearer <access_token>
Content-Type: application/json
```

O `<access_token>` deve ser substituído pelo token de acesso válido obtido após o login bem sucedido.

Note que o corpo da requisição deve conter as informações a serem atualizadas para o usuário atualmente autenticado. O email é um campo único, portanto, se um email já estiver sendo usado por outro usuário, ocorrerá um erro de validação. Caso o campo de senha seja fornecido, a senha atual será alterada para a nova senha fornecida.

#	_______________________________________________________________________________________________________________

#	Chat Django Channels e Rediz 



1. Crie um novo aplicativo dentro do projeto Django executando o seguinte comando:

```
python manage.py startapp chat
```

Substitua "chat" pelo nome do seu aplicativo.

1. Adicione o Django Channels e o Redis às dependências do projeto no arquivo `requirements.txt`:

```
channels==3.0.3
channels_redis==3.3.1
redis==3.5.3
```

Em seguida, execute o seguinte comando para instalar as dependências:

```
pip install -r requirements.txt
```

1. Crie um novo arquivo chamado `routing.py` dentro do diretório do aplicativo `chat` e adicione o seguinte código:

```
from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<room_name>\w+)/$', consumers.ChatConsumer.as_asgi()),
]
```

Este arquivo define o padrão de URL para a conexão WebSocket e mapeia o caminho da URL para o consumidor que lidará com as mensagens da sala de chat.

####	OBS: `Nao copiar` 

- Apenas Idea:

```
from django.urls import path
from django.conf.urls import include
from rest_framework.authtoken.views import obtain_auth_token
from chat.views import ChatConsumer

websocket_urlpatterns = [
    path('ws/chat/<str:room_name>/', ChatConsumer.as_asgi()),
]

urlpatterns = [
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
```



1. Crie um novo arquivo chamado `consumers.py` dentro do diretório do aplicativo `chat` e adicione o seguinte código:

```
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = 'chat_%s' % self.room_name

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        username = self.scope["user"].username

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'username': username
            }
        )

    # Receive message from room group
    async def chat_message(self, event):
        message = event['message']
        username = event['username']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'username': username
        }))
```

Este arquivo define o consumidor WebSocket que gerenciará a sala de chat. Ele lida com a conexão, desconexão e envio/recebimento de mensagens do usuário.

Observe que o consumidor usa o Redis para gerenciar o tráfego de mensagens. Você precisará configurar o Redis em seu projeto Django para que ele possa ser usado pelo Django Channels.

1. Adicione o suporte a Django Channels ao seu projeto Django edit



O arquivo settings.py` e adicione as seguintes configurações:

```
INSTALLED_APPS = [
    # ...
    'channels',
    'chat',
]

ASGI_APPLICATION = 'backend.routing.application'

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('localhost', 6379)],
        },
    },
}
```

Essas configurações adicionam o Django Channels à lista de aplicativos instalados e definem o aplicativo ASGI que gerenciará as conexões WebSocket. Além disso, ele define as configurações do Redis para que o Django Channels possa usá-lo para gerenciar o tráfego de mensagens.

1. Adicione as rotas do aplicativo ao arquivo `myproject/urls.py` adicionando as seguintes linhas:

```
from django.urls import path, include

urlpatterns = [
    # ...
    path('chat/', include('chat.urls')),
]
```

1. Crie um novo arquivo chamado `urls.py` dentro do diretório do aplicativo `chat` e adicione as seguintes rotas:

```
from django.urls import path

from . import views

urlpatterns = [
    path('rooms/', views.RoomList.as_view(), name='room-list'),
    path('rooms/<str:name>/', views.RoomDetail.as_view(), name='room-detail'),
]
```

Este arquivo define as rotas para listar as salas de chat e para acessar uma sala de chat específica.

1. Crie um novo arquivo chamado `models.py` dentro do diretório do aplicativo `chat` e adicione o seguinte código:

```
from django.db import models

class Room(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name
```

Este arquivo define o modelo para a sala de chat, que tem apenas um campo `name` para armazenar o nome da sala de chat.

1. Crie um novo arquivo chamado `serializers.py` dentro do diretório do aplicativo `chat` e adicione o seguinte código:

```
from rest_framework import serializers
from .models import Room

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = ['id', 'name']
```

Este arquivo define o serializador para a sala de chat, que converte o modelo da sala de chat em um formato JSON.

1. Crie um novo arquivo chamado `views.py` dentro do diretório do aplicativo `chat` e adicione o seguinte código:

```
from rest_framework import generics
from .models import Room
from .serializers import RoomSerializer

class RoomList(generics.ListCreateAPIView):
    queryset = Room.objects.all()
    serializer_class = RoomSerializer

class RoomDetail(generics.RetrieveDestroyAPIView):
    queryset = Room.objects.all()
    serializer_class = RoomSerializer
    lookup_field = 'name'
```

Este arquivo define as visões da API para listar as salas de chat e acessar uma sala de chat específica. As visualizações usam o Django REST Framework para serializar e desserializar os dados da sala de chat.

1. Execute as migrações do Django executando o seguinte comando no terminal:

```
python manage.py migrate
```

1. Crie uma nova sala de chat executando o seguinte comando no terminal:

```
python manage.py shell
```

Em seguida, dentro do shell do Django, execute os seguintes comandos:

```
from backend.chat.models import Room
Room.objects.create(name='sala-de-teste')
```

Este comando cria uma nova sala de chat com o nome `sala-de-teste`.

1. Crie um novo diretório chamado `consumers` dentro do diretório do aplicativo `chat`. Em seguida, crie um novo arquivo chamado `__init__.py` neste diretório vazio.
2. Crie um novo arquivo chamado `chat_consumer.py` dentro do diretório `consumers` e adicione o seguinte código:

```
import json
from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer
from chat.models import Room

class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['name']
        self.room_group_name = 'chat_%s' % self.room_name

        # Join room group
        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )

        self.accept()

    def disconnect(self, close_code):
        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        # Send message to room group
        async_to_sync(self.channel_layer.group_send)(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message
            }
        )

    # Receive message from room group
    def chat_message(self, event):
        message = event['message']

        # Send message to WebSocket
        self.send(text_data=json.dumps({
            'message': message
        }))
```

Este arquivo define o consumidor de WebSocket para gerenciar as conexões do WebSocket. O consumidor é responsável por conectar e desconectar clientes, receber mensagens de clientes e enviar mensagens de volta para o grupo de sala de bate-papo apropriado.

1. Crie um novo arquivo chamado `routing.py` dentro do diretório `chat` e adicione o seguinte código:

```
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<name>\w+)/$', consumers.ChatConsumer.as_asgi()),
]
```

Este arquivo define as rotas WebSocket para o consumidor de bate-papo. Ele define uma rota que corresponde a uma expressão regular que inclui o nome da sala de bate-papo.

1. Atualize o arquivo `myproject/routing.py` com o seguinte código:

```
from django.urls import path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from chat import routing as chat_routing

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            chat_routing.websocket_urlpatterns
        )
    ),
})
```

Este arquivo define o roteador ASGI para o aplicativo. Ele usa o roteador URL do Django Channels para rotear conexões WebSocket para o consumidor de bate-papo apropriado.

1. Execute o servidor Django Channels executando o seguinte comando no terminal:

```
daphne myproject.asgi:application
```

Este comando inicia o servidor Daphne, que é o servidor ASGI usado pelo Django Channels. Ele deve exibir uma mensagem informando que o servidor está sendo execut



1. Em outro terminal, acesse o shell do Django executando o seguinte comando:

```
python manage.py shell
```

1. No shell do Django, crie um novo usuário executando o seguinte código:

```
from django.contrib.auth.models import User
User.objects.create_user('johndoe', password='testpassword')
```

Este comando cria um novo usuário com nome de usuário `johndoe` e senha `testpassword`.

1. Ainda no shell do Django, crie uma nova sala de chat executando o seguinte código:

```
from chat.models import Room
Room.objects.create(name='test-room')
```

Este comando cria uma nova sala de chat com o nome `test-room`.

1. Deixe o shell do Django aberto e abra o seu navegador. Acesse o endereço `http://localhost:8000/chat/test-room/` e faça login com as credenciais do usuário que você criou anteriormente.
2. Abra uma nova guia do navegador e acesse o mesmo endereço `http://localhost:8000/chat/test-room/`. Faça login com as mesmas credenciais do usuário.
3. Digite algumas mensagens na caixa de texto e clique em Enviar. As mensagens devem ser exibidas em ambas as guias do navegador.

Parabéns, você criou com sucesso uma API de chat Django usando o Django Channels e o Redis para autenticação de usuários! Agora você pode construir sobre este projeto para adicionar recursos adicionais, como envio de arquivos, emojis, notificações de presença e muito mais.

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e)![catson@outlook.pt](https://chat.openai.com/_next/image?url=https%3A%2F%2Fs.gravatar.com%2Favatar%2Fccefd8635a6c7e514705e2e03d9fe457%3Fs%3D480%26r%3Dpg%26d%3Dhttps%253A%252F%252Fcdn.auth0.com%252Favatars%252Fca.png&w=64&q=75)

continue



1. Para encerrar a sessão, volte para o shell do Django e execute o seguinte código:

```
python
from django.contrib.sessions.models import Session
Session.objects.all().delete()
```

Este comando remove todas as sessões de usuários do banco de dados. Isso é importante para garantir que outros usuários não possam acessar a conta do usuário anterior que estava autenticado.

1. Para parar o servidor da API, volte para o terminal onde você iniciou o servidor e pressione `Ctrl + C`. Isso interromperá o servidor.

Parabéns, você agora tem uma API de chat Django Channels totalmente funcional com autenticação de usuário usando Redis!

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e)![catson@outlook.pt](https://chat.openai.com/_next/image?url=https%3A%2F%2Fs.gravatar.com%2Favatar%2Fccefd8635a6c7e514705e2e03d9fe457%3Fs%3D480%26r%3Dpg%26d%3Dhttps%253A%252F%252Fcdn.auth0.com%252Favatars%252Fca.png&w=64&q=75)

continue



1. Para implantar a API de chat em um ambiente de produção, você pode usar uma plataforma de hospedagem em nuvem, como o Amazon Web Services (AWS) ou o Google Cloud Platform (GCP). Ambas as plataformas oferecem serviços gerenciados para executar contêineres Docker, que podem ser usados para implantar sua aplicação Django com o Django Channels e o Redis.
2. Primeiro, você precisará configurar o seu projeto Django para ser executado em um contêiner Docker. Para fazer isso, crie um arquivo `Dockerfile` na raiz do seu projeto Django com o seguinte conteúdo:

```
bash
# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Run app.py when the container launches
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
```

Este arquivo especifica que a imagem Docker deve usar a versão 3.9 do Python como base, copiar todos os arquivos do projeto para dentro do contêiner, instalar as dependências listadas no arquivo `requirements.txt` e, em seguida, executar o comando `python manage.py runserver 0.0.0.0:8000` para iniciar o servidor da API.

1. Em seguida, crie um arquivo `docker-compose.yml` na raiz do seu projeto com o seguinte conteúdo:

```
yaml
version: '3'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - redis
  redis:
    image: "redis:alpine"
```

Este arquivo especifica que o serviço `web` deve ser construído a partir do `Dockerfile` na pasta atual (`.`), expor a porta `8000` para fora do contêiner, depende do serviço `redis` e que o serviço `redis` deve ser executado a partir da imagem oficial do Redis.

1. Para implantar a API de chat no AWS usando o Amazon Elastic Container Service (ECS), siga os seguintes passos:

- Faça login no console da AWS e crie um novo cluster ECS.
- Crie um novo repositório ECR (Elastic Container Registry) para armazenar a imagem do contêiner.
- Use o AWS CLI para fazer login no ECR e fazer push da imagem do contêiner para o repositório ECR. Por exemplo:

```
php
aws ecr get-login-password --region <REGION> | docker login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
docker build -t <AWS_ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/<REPOSITORY_NAME>:<TAG> .
docker push <AWS_ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/<REPOSITORY_NAME>:<TAG>
```

- Crie uma nova definição de tarefa ECS que use a imagem do contêiner do ECR. Certifique-se de configurar a variável de ambiente `REDIS_URL` para apontar para o endpoint do Redis no seu ambiente de produção. Você também precisará configurar a porta de contêiner para



