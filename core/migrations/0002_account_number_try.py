# Generated by Django 2.2.14 on 2020-08-03 19:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='number_try',
            field=models.IntegerField(default=0),
        ),
    ]