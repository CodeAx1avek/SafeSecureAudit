from django.urls import path
from .views import index,learning,termsandcondition,Allaboutbugbounty,bughuntingmethodology,huntchecklist,user_login,user_signup,user_logout,dashboard,profile
from .views import delete_scan

urlpatterns = [
    path("",index,name="index"),
    path('login/',user_login, name='login'),
    path('signup/',user_signup, name='signup'),
    path('dashboard/', dashboard, name='dashboard'),
    path('logout/',user_logout, name='logout'),
    path("learning",learning,name="learning"),
    path("termsandcondition",termsandcondition,name="termsandcondition"),
    path("Allaboutbugbounty",Allaboutbugbounty,name="Allaboutbugbounty"),
    path("bughuntingmethodology",bughuntingmethodology,name="bughuntingmethodology"),
    path("huntchecklist",huntchecklist,name="huntchecklist"),
    path("profile",profile,name="profile"),
    path('delete_scan/<int:scan_id>/', delete_scan, name='delete_scan'),
]