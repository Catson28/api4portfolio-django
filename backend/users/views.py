from rest_framework_simplejwt.views import TokenObtainPairView

class TokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer