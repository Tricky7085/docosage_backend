from django.db import models
from django.contrib.auth.hashers import make_password



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
        return self.name
    
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


class DoctorInformation(models.Model):
    user = models.OneToOneField(Users,on_delete=models.CASCADE)
    age = models.DateField(null=False)
    gender = models.CharField(max_length=10,null=False)
    qualification = models.CharField(max_length=255,null=False)
    yearsOfExperience=models.IntegerField(null=False)
    registrationYear=models.DateField(null=False)
    registrationNumber = models.CharField(max_length=255,null=False)
    registeredCouncil = models.CharField(max_length=255,null=False)
    practiceType=models.CharField(max_length=255,null=False)
    clinicAddress=models.CharField(max_length=255,null=False)
    clinicZipCode=models.IntegerField(null=False,blank=False)
    
    
    def __str__(self):
        return f"Dr. {self.user.name} - {self.yearsOfExperience} - {self.practiceType}"
    
    class Meta:
        db_table = 'doctor_information'
        app_label = 'DocOsge'
        indexes = [
            models.Index(fields=['practiceType']),
            models.Index(fields=['user']),
        ]

class Appointment(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    doctor = models.ForeignKey(DoctorInformation, on_delete=models.CASCADE)
    appointment_date = models.DateTimeField()
    appointment_time = models.TimeField()
    title = models.CharField(max_length=255, null=False, blank=False)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Appointment with Dr. {self.doctor.user.name} on {self.appointment_date} at {self.appointment_time}"

    class Meta:
        db_table = 'appointments'
        app_label = 'DocOsge'
