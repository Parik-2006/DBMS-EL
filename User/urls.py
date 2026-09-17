from django.urls import path 
from .import views 

urlpatterns=[
    path('',views.index,name='index'),
    path('register',views.register,name='register'),
    path('login',views.login,name='login'),
    path('adminlogin',views.adminlogin,name='adminlogin'),
    path('data',views.data,name='data'),
    path('predict',views.predict,name="predict"),
    path('logout',views.logout,name='logout'),
    path('adminhome',views.adminhome,name='adminhome'),
    path('health',views.health,name='health'),
    path('status',views.status,name='status'),
]