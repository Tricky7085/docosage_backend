# Generated by Django 5.0.6 on 2024-08-01 16:02

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DocOsge', '0003_doctorinformation'),
    ]

    operations = [
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('appointment_date', models.DateTimeField()),
                ('appointment_time', models.TimeField()),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'appointments',
            },
        ),
        migrations.AddIndex(
            model_name='doctorinformation',
            index=models.Index(fields=['practiceType'], name='doctor_info_practic_eba4dd_idx'),
        ),
        migrations.AddIndex(
            model_name='doctorinformation',
            index=models.Index(fields=['user'], name='doctor_info_user_id_1bd2e3_idx'),
        ),
        migrations.AddField(
            model_name='appointment',
            name='doctor',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='DocOsge.doctorinformation'),
        ),
        migrations.AddField(
            model_name='appointment',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='DocOsge.users'),
        ),
    ]
