from django.db import models
from django.contrib.auth.hashers import make_password
from django.conf import settings


# Create your models here.


class LoginUsers(models.Model):
    loginId = models.AutoField(primary_key=True)
    loginName = models.CharField(max_length=50)

    class Meta:
        db_table = 'login_users'
        app_label = 'DocOsge_Backend.DocOsge'

class Users(models.Model):
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255,null=False,blank=False)
    email = models.EmailField(max_length=255,unique=True,null=False,blank=False)
    phone_number = models.CharField(max_length=20,unique=True)
    password_hash = models.CharField(max_length=255,null=False,blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.email
    
    class Meta:
        db_table = 'registered_users'
        app_label = 'DocOsge'


    def save(self,*args,**kwargs):
        if not self.pk:
            self.password_hash = make_password(self.password_hash)
        super().save(*args,**kwargs)    

    
class AccountTypes(models.Model):
    account_type_id = models.AutoField(primary_key=True)
    account_type = models.CharField(max_length=50,null=False,blank=False)
    
    def __str__(self):
        return self.account_type
    
class UserAccountTypes(models.Model):
    user= models.ForeignKey(Users,on_delete=models.CASCADE) 
    account_type = models.ForeignKey(AccountTypes,on_delete=models.CASCADE)
    
    class Meta:
        unique_together = (('user','account_type'))
    
class SocialAccounts(models.Model):
    social_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(Users('user_id'),on_delete=models.CASCADE)
    provider = models.CharField(max_length=50,null=False, blank=False)
    provider_id = models.CharField(max_length=255,null=False,blank=False)
   
    
class UserInformation(models.Model):
    user = models.ForeignKey(Users('user_id'),on_delete=models.CASCADE)
    height = models.IntegerField(null=True,blank=True)
    weight = models.IntegerField(null=True,blank=True)
    age = models.IntegerField(null=True,blank=True)
    getInBed = models.TimeField(null=True,blank=True)
    wakeUp = models.TimeField(null=True,blank=True)
    calories = models.IntegerField(null=True,blank=True)
    steps =models.IntegerField(null=True,blank=True)
    gender = models.CharField(max_length=10,null=True,blank=True)


# class Doctor(models.Model):
#     user = models.OneToOneField(Users, on_delete=models.CASCADE)


class Appointment(models.Model):

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Users, related_name='appointments', on_delete=models.CASCADE)
    appointment_date  = models.DateField()
    appointment_time  = models.TimeField()
    title = models.CharField(max_length=100)
    description = models.TextField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

class Attachment():
    appointment = models.ForeignKey(Appointment, related_name='attachments', on_delete=models.CASCADE)
    file = models.FileField(upload_to='attachments/')
    created_at = models.DateTimeField(auto_now_add=True)




    # def __str__(self):
    #     return f"Profile of {self.user.name}"
    
    # class Meta:
    #     db_table = 'user_profile'
    #     app_label = 'DocOsge'


# class Appointment(models.Model):
#     user = models.ForeignKey(Users, on_delete=models.CASCADE)
#     doctor = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='doctor_appointments')
#     appointment_date = models.DateTimeField()
#     status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('confirmed', 'Confirmed'), ('cancelled', 'Cancelled')], default='pending')


#     def __str__(self) -> str:
#         return f"Appointment with {self.doctor.name} on {self.appointment_date}"
    
#     class Meta:
#         db_table = 'appointments'
#         app_label = 'DocOsge'





# class Doctor(models.Model):
#     user = models.OneToOneField(Users, on_delete=models.CASCADE, related_name='doctor_profile')
#     profile_picture = models.ImageField(upload_to='doctors_pics/', null=True, blank=True)
#     specialty = models.CharField(max_length=255, null=False, blank=False)
#     experience = models.PositiveIntegerField(null=False, blank=False)
#     consultation_fee = models.DecimalField(max_digits=6, decimal_places=2, null=False, blank=False)
#     profile_likes = models.PositiveIntegerField(default=0)
#     patients_visited = models.PositiveIntegerField(default=0)

#     def __str__(self):
#         return f"Dr.{self.user.name} - {self.specialty}"
    
#     class Meta:
#         db_table = 'doctors'
#         app_label = 'DocOsge'


# class Appointment(models.Model):
#     doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='appointments')
#     patient = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='appointments')
#     appointment_date = models.DateTimeField()
#     created_at = models.DateTimeField(default=timezone.now)
#     status = models.CharField(max_length=50, default='scheduled')

#     def __str__(self):
#         return f"Appointment with Dr.{self.doctor.user.name} on {self.appointment_date}"
    
#     class Meta:
#         db_table = 'appointments'
#         app_label = 'DocOsge'