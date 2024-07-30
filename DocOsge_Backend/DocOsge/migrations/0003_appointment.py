# Generated by Django 5.0.6 on 2024-07-29 20:34

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DocOsge', '0002_userinformation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('appointment_date', models.DateField()),
                ('appointment_time', models.TimeField()),
                ('title', models.CharField(max_length=100)),
                ('description', models.TextField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='appointments', to='DocOsge.users')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
