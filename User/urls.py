from django.urls import path 
from . import views
from . import api

urlpatterns=[
    path('',views.index,name='index'),
    path('register',views.register,name='register'),
    path('login',views.login,name='login'),
    path('adminlogin',views.adminlogin,name='adminlogin'),
    path('data',views.data,name='data'),
    path('clear-history',views.clear_history,name='clear_history'),
    path('predict',views.predict,name="predict"),
    path('logout',views.logout,name='logout'),
    path('adminhome',views.adminhome,name='adminhome'),
    path('health',views.health,name='health'),
    path('status',views.status,name='status'),
    
    path('api/fallback/result/', api.fallback_result, name='fallback_result'),
    path('api/fallback/uncertain-scans/', api.uncertain_scans, name='uncertain_scans'),
    path('api/fallback/scan-status/<int:scan_id>/', api.scan_status, name='scan_status'),
    path('api/correlation/domain/<int:domain_id>/', api.domain_correlation, name='domain_correlation'),
    path('api/correlation/malicious-ips/', api.malicious_ips, name='malicious_ips'),
    
    path('api/nikhil/submit-review/', api.submit_review, name='submit_review'),
    path('api/nikhil/investigation/<int:scan_id>/', api.investigation_detail, name='investigation_detail'),
]
