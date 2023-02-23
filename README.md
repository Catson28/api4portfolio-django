##	Api django login logout e chat protegido

Para criar uma API Django com login, logout e chat protegido, você pode seguir os seguintes passos:

1. Crie um novo projeto Django usando o comando `django-admin startproject` e um novo aplicativo usando o comando `python manage.py startapp`.

```
python3 -m venv env
source env/bin/activate
pip install Django

django-admin startproject backend .
python manage.py startapp backend.app

#	intalar os aplicativos dentro da pasta do projecto
mkdir backend/app
python manage.py startapp chat backend/app

ou
cd backend
python ../manage.py startapp chat
python ../manage.py startapp message
python ../manage.py startapp operations
```

Quando se criam os aplicativos desta forma é importante adicionar o nome do projecto no arquivo `apps.py` por exemplo:

```
from django.apps import AppConfig


class AppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "project.app"
```

Adicionar isso em `settings.py`

```
# settings.py

# ...

INSTALLED_APPS = [
    # ...
    
	# aplicativos personalizados
    'users',
    'chat',
    'reports',
    'operations',
    'messages',
    # ...
]
```



###	Comecar

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

E

```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
}
```

_

Crie um modelo de dados no arquivo `models.py` do aplicativo:

```
from django.db import models

class Exemplo(models.Model):
    nome = models.CharField(max_length=100)
    idade = models.IntegerField()
    email = models.EmailField()
```

Execute as migrações para criar a tabela no banco de dados:

```
python manage.py makemigrations
python manage.py migrate
```

Crie uma visualização (`view`) para sua API em `views.py`:

```
from rest_framework import viewsets
from .models import Exemplo
from .serializers import ExemploSerializer

class ExemploViewSet(viewsets.ModelViewSet):
    queryset = Exemplo.objects.all()
    serializer_class = ExemploSerializer
```

Crie um arquivo de serialização em `serializers.py`:

```
from rest_framework import serializers
from .models import Exemplo

class ExemploSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exemplo
        fields = '__all__'
```

Configure as rotas em `urls.py`:

```
from django.urls import include, path
from rest_framework import routers
from .views import ExemploViewSet

router = routers.DefaultRouter()
router.register(r'exemplo', ExemploViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
```

Ou:

```
from django.urls import include, path
from rest_framework import routers
from .views import ExemploViewSet

router = routers.DefaultRouter()
router.register(r'exemplo', ExemploViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')), # adicione esta linha
]

```

Execute o servidor Django:

```
python manage.py runserver
```

##	Cria login

Instale as bibliotecas necessárias:

```
pip install djangorestframework
pip install djangorestframework-jwt
```

Adicione `'rest_framework'` e `'rest_framework_jwt'` à lista de `INSTALLED_APPS` no seu arquivo `settings.py`:

```
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'rest_framework_jwt',
]
```

Configure as opções de autenticação JWT no seu arquivo `settings.py`:

```
JWT_AUTH = {
    'JWT_ENCODE_HANDLER':
    'rest_framework_jwt.utils.jwt_encode_handler',

    'JWT_DECODE_HANDLER':
    'rest_framework_jwt.utils.jwt_decode_handler',

    'JWT_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_payload_handler',

    'JWT_SECRET_KEY': SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(hours=1),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,
    'JWT_ALLOW_REFRESH': False,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',
}
```

Model:

```
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30, blank=True, null=True)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # adicionando related_name para groups e user_permissions
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='users_group',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='users_permission',
        blank=True
    )

    def __str__(self):
        return self.email


class Exemplo(models.Model):
    nome = models.CharField(max_length=100)
    idade = models.IntegerField()
    email = models.EmailField()
```

Crie uma classe para o serializer do usuário no seu arquivo `serializers.py`:

```
from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}
```

Crie uma classe para a view do usuário no seu arquivo `views.py`:

```
from django.contrib.auth.models import User
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from .serializers import UserSerializer

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
```

Adicione as rotas de autenticação no seu arquivo `urls.py`:

```
from django.urls import path
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, verify_jwt_token
from .views import UserRegistrationView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', obtain_jwt_token, name='login'),
    path('refresh-token/', refresh_jwt_token, name='refresh-token'),
    path('verify-token/', verify_jwt_token, name='verify-token'),
]
```

###	Proteger as rota

Para proteger as rotas, você pode usar o decorador `@jwt_auth` em suas views:

```
from rest_framework.decorators import
```

O decorador `@jwt_auth` é usado para proteger as rotas de uma API usando autenticação JWT. O decorador é fornecido pelo pacote `djangorestframework_simplejwt`, que fornece funcionalidades para autenticação JWT para Django Rest Framework.

Para usá-lo, primeiro você precisa importá-lo em suas views. Isso pode ser feito com a seguinte linha de código:

```
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated

@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def my_view(request):
    # implementação da view protegida por autenticação JWT
```

Observe que estamos importando `JWTAuthentication` do pacote `rest_framework_simplejwt.authentication`, que fornece a funcionalidade de autenticação JWT, e importando `IsAuthenticated` do pacote `rest_framework.permissions`, que fornece uma classe de permissão que garante que o usuário esteja autenticado.

Em seguida, usamos o decorador `@authentication_classes([JWTAuthentication])` para especificar que estamos usando autenticação JWT em nossa view, e usamos o decorador `@permission_classes([IsAuthenticated])` para especificar que a view só deve ser acessada por usuários autenticados.

Dessa forma, quando um usuário faz uma solicitação para essa view, o sistema verificará se o usuário está autenticado e se ele tem permissão para acessar a view. Se o usuário não estiver autenticado ou não tiver permissão para acessar a view, o sistema retornará uma resposta de erro.

Aqui está um exemplo básico de uma view de endpoint GET e POST que usa `@authentication_classes([JWTAuthentication])` e `@permission_classes([IsAuthenticated])` para proteger o acesso apenas para usuários autenticados:

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import JWTAuthentication

class ExampleView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        # Implementação da lógica do método GET
        return Response({'message': 'GET realizado com sucesso!'})

    def post(self, request, format=None):
        # Implementação da lógica do método POST
        return Response({'message': 'POST realizado com sucesso!'})
```

Nesse exemplo, criamos uma view chamada `ExampleView` que herda da classe `APIView`. Em seguida, definimos a lista de `authentication_classes` como `[JWTAuthentication]` e a lista de `permission_classes` como `[IsAuthenticated]`.

Nao se esquecer de installar o:

```
pip install djangorestframework-simplejwt
```

:

```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication', 
    ],
}
```

Dessa forma, quando um usuário faz uma solicitação GET ou POST para essa view, o sistema verifica se o usuário está autenticado usando a autenticação JWT e se ele tem permissão para acessar a view usando a permissão `IsAuthenticated`.

Se o usuário estiver autenticado e tiver permissão para acessar a view, a lógica de cada método GET e POST será executada e uma resposta será retornada com a mensagem "GET realizado com sucesso!" ou "POST realizado com sucesso!", respectivamente.

Se o usuário não estiver autenticado ou não tiver permissão para acessar a view, o sistema retornará uma resposta de erro.

Aqui está um exemplo de como você pode criar uma URL para a classe `ExampleView` em seu arquivo `urls.py`:

```
python
from django.urls import path
from .views import ExampleView

urlpatterns = [
    path('example/', ExampleView.as_view(), name='example-view'),
]
```

Nesse exemplo, criamos uma rota para a view `ExampleView` com o caminho `example/`. Ao acessar essa URL em um navegador ou ao fazer uma solicitação HTTP GET ou POST usando um cliente HTTP, a view `ExampleView` será chamada e executará a lógica definida em seus métodos GET e POST, se o usuário estiver autenticado e autorizado.

Observe que usamos o método `as_view()` para converter a classe `ExampleView` em uma função de visualização que pode ser chamada por uma rota do Django. Também definimos um nome para a URL usando o parâmetro `name`, o que pode ser útil para criar links para a URL em seu código Python ou em seus templates Django.

#### Erro:

```
ImportError: cannot import name 'JWTAuthentication' from 'rest_framework.authentication' (/home/cand/Python_Project/2023/Ajuda ChatGPT/MeuPortfolio/env/lib/python3.9/site-packages/rest_framework/authentication.py)
```

####	Solucao:

```
# Em vez de
from rest_framework.authentication import JWTAuthentication

coloque
from rest_framework_simplejwt.authentication import JWTAuthentication
```

E ee desta forma que se acessa uma rota do simplejwt, se o resultado for este ee porque o token espirou

![img1](img1.png)

Para o nosso caso tem que aparecer assim:
![img2](img2.png)

Ou

 você pode adicionar um cabeçalho de autorização (Authorization header) à sua solicitação HTTP. O valor do cabeçalho de autorização deve ser "Bearer " seguido pelo token JWT.

Aqui está como adicionar um cabeçalho de autorização no Postman:

1. Abra o Postman e selecione a solicitação que deseja enviar com autenticação JWT.
2. Clique na guia "Headers" (Cabeçalhos) abaixo da barra de URL.
3. Clique no botão "Add Headers" (Adicionar cabeçalhos) e selecione "Authorization" na lista.
4. No campo "Value" (Valor), insira "Bearer " seguido pelo token JWT. Por exemplo: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6Im1hcmNvIiwiZXhwIjoxNjIwNjg5MzYxLCJlbWFpbCI6IiJ9.1e-nsfNeGzOAxqM3fxRGi-kvaCtJrRt65G2t1u_WCH4"
5. Clique em "Send" (Enviar) para enviar a solicitação com o cabeçalho de autorização incluído.

###	OBS:

O pacote `rest_framework_jwt` é uma biblioteca de autenticação JWT mais antiga para o Django REST Framework, enquanto o `rest_framework_simplejwt` é uma biblioteca mais nova e mais fácil de usar para a autenticação JWT.

As principais diferenças entre as duas bibliotecas estão na forma como elas geram e verificam os tokens JWT, bem como nas opções de configuração e personalização disponíveis.

O `rest_framework_jwt` usa a biblioteca PyJWT para gerar e verificar tokens JWT, enquanto o `rest_framework_simplejwt` possui seu próprio sistema de geração e verificação de tokens, que é mais fácil de configurar e personalizar.

Em relação à implementação nas views, ambas as bibliotecas usam os decoradores `@authentication_classes` e `@permission_classes` para autenticar e autorizar as solicitações HTTP.

No entanto, se você optar por usar o `rest_framework_jwt`, precisará usar o decorador `@jwt_authenticatiton` para autenticar as solicitações HTTP. Além disso, você precisará configurar manualmente as opções de autenticação e autorização para o pacote `rest_framework_jwt`.

Por outro lado, se você usar o `rest_framework_simplejwt`, poderá usar o decorador `@authentication_classes` com `JWTAuthentication` para autenticar as solicitações HTTP. O `rest_framework_simplejwt` também possui opções de configuração mais fáceis de usar para personalizar a autenticação e a autorização.

Em resumo, se você estiver criando um novo projeto Django REST Framework, é recomendável usar o `rest_framework_simplejwt`, pois é mais fácil de usar e tem mais recursos de personalização. Se você estiver trabalhando em um projeto existente que usa o `rest_framework_jwt`, poderá continuar usando-o ou migrar para o `rest_framework_simplejwt` se preferir uma biblioteca mais atualizada e fácil de usar.

###	Logout

> ​	rest_framework_jwt

Para criar um endpoint para logout no `rest_framework_jwt`, você pode usar o método `JWTAuthentication.invalidate()` para invalidar o token de autenticação JWT do usuário. O método `invalidate()` revoga o token JWT, o que significa que o usuário precisará obter um novo token JWT para se autenticar novamente.

Para implementar um endpoint de logout usando o `rest_framework_jwt`, siga estas etapas:

1. Importe o método `JWTAuthentication` e o pacote `jwt` na sua view:

```
from rest_framework_jwt.authentication import JWTAuthentication
from jwt import InvalidTokenError
```

1. Crie uma nova view para lidar com a solicitação de logout:

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            request.user.auth_token.delete()
            return Response(status=status.HTTP_200_OK)
        except (AttributeError, InvalidTokenError):
            return Response(status=status.HTTP_400_BAD_REQUEST)
```

1. Adicione a nova view ao arquivo `urls.py` do seu aplicativo:

```
from django.urls import path
from .views import LogoutView

urlpatterns = [
    path('logout/', LogoutView.as_view(), name='logout'),
]
```

1. Agora, quando um usuário fizer uma solicitação para a URL `/logout/` usando o método POST, o token JWT do usuário será invalidado e ele será desconectado.

Observe que, ao usar o `rest_framework_jwt`, o token JWT é armazenado como um objeto `Token` do modelo Django, que é criado automaticamente quando o usuário se autentica com sucesso. Para invalidar o token JWT, estamos chamando o método `delete()` no objeto `Token` associado ao usuário atual.

> ​	rest_framework_simplejwt

Para criar um endpoint de logout no `rest_framework_simplejwt`, você precisa implementar algumas etapas:

1. Importe as classes `JWTAuthentication` e `TokenObtainPairView` do `rest_framework_simplejwt`:

```
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
```

1. Substitua o método `post()` da classe `TokenObtainPairView` pelo seguinte código para que o token seja invalidado após a saída:

```
class CustomTokenObtainPairView(TokenObtainPairView):
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            refresh_token = response.data['refresh']
            access_token = response.data['access']
            response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, samesite='None', secure=True)
            response.data = {'access_token': access_token}
        return response

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            response.delete_cookie('refresh_token')
        return response
```

Observe que a classe `CustomTokenObtainPairView` herda da classe `TokenObtainPairView` do `rest_framework_simplejwt` e sobrescreve o método `post()`. No método `post()`, depois que o token de acesso e o token de atualização são gerados com sucesso, o token de atualização é definido em um cookie seguro e o token de acesso é retornado.

1. Crie uma nova view para lidar com a solicitação de logout:

```
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def post(self, request):
        try:
            token = RefreshToken(request.data["refresh_token"])
            token.blacklist()
            return Response(status=204)
        except Exception:
            return Response(status=400)
```

1. Adicione a nova view ao arquivo `urls.py` do seu aplicativo:

```
from django.urls import path
from .views import CustomTokenObtainPairView, CustomTokenRefreshView, LogoutView

urlpatterns = [
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
```

1. Agora, quando um usuário fizer uma solicitação para a URL `/logout/` usando o método POST, o token de atualização será invalidado e o cookie `refresh_token` será excluído.

Observe que o `rest_framework_simplejwt` armazena o token JWT como um objeto `RefreshToken`, que é criado automaticamente quando o usuário se autentica com sucesso. Para invalidar o token JWT, estamos chamando o método `blacklist()` no objeto `RefreshToken` associado ao token de atualização enviado pelo usuário na solicitação de logout.
