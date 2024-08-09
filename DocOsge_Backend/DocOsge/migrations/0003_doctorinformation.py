# Generated by Django 5.0.6 on 2024-08-01 13:31

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DocOsge', '0002_userinformation'),
    ]

    operations = [
        migrations.CreateModel(
            name='DoctorInformation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('age', models.DateField()),
                ('gender', models.CharField(max_length=10)),
                ('qualification', models.CharField(max_length=255)),
                ('yearsOfExperience', models.IntegerField()),
                ('registrationYear', models.DateField()),
                ('registrationNumber', models.CharField(max_length=255)),
                ('registeredCouncil', models.CharField(max_length=255)),
                ('practiceType', models.CharField(max_length=255)),
                ('clinicAddress', models.CharField(max_length=255)),
                ('clinicZipCode', models.IntegerField()),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='DocOsge.users')),
            ],
            options={
                'db_table': 'doctor_information',
            },
        ),
    ]
